// OAuth 2.1 authorization-server proxy in front of an MCP server.
//
// claude.ai talks standard MCP-connector OAuth to THIS service (DCR + PKCE).
// We proxy the actual user login to Microsoft Entra (which lacks DCR), using
// two-leg PKCE, and reuse a single pre-registered Entra app. After auth, /mcp
// requests are verified against Entra and reverse-proxied to the upstream MCP
// server with that server's static bearer token injected.

import express from 'express';
import crypto from 'node:crypto';
import httpProxy from 'http-proxy';

const PORT = parseInt(process.env.PORT || '3000', 10);
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const TENANT_ID = process.env.ENTRA_TENANT_ID;
const CLIENT_ID = process.env.ENTRA_CLIENT_ID;
const CLIENT_SECRET = process.env.ENTRA_CLIENT_SECRET;
const UPSTREAM_BASE = process.env.UPSTREAM_MCP_BASE; // e.g. http://pipedrive-mcp-server.internal:3000
const UPSTREAM_JWT = process.env.UPSTREAM_MCP_JWT;   // static bearer the upstream expects
const ALLOWED_REDIRECT_URIS = (process.env.ALLOWED_REDIRECT_URIS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

for (const [k, v] of Object.entries({ PUBLIC_URL, TENANT_ID, CLIENT_ID, CLIENT_SECRET, UPSTREAM_BASE, UPSTREAM_JWT })) {
  if (!v) { console.error(`FATAL: missing required env ${k}`); process.exit(1); }
}

const AUTHORITY = `https://login.microsoftonline.com/${TENANT_ID}`;
const SCOPES = 'openid profile offline_access User.Read';

const app = express();
app.set('trust proxy', true); // behind Sliplane TLS-terminating proxy

// --- two-leg PKCE store: state -> { clientChallenge, serverVerifier, createdAt }
const pkceStore = new Map();
function gcPkce() {
  const now = Date.now();
  for (const [k, v] of pkceStore) if (now - v.createdAt > 10 * 60 * 1000) pkceStore.delete(k);
}

function isAllowedRedirect(uri) {
  if (!uri) return false;
  try {
    const u = new URL(uri);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  } catch { return false; }
  if (ALLOWED_REDIRECT_URIS.length > 0) return ALLOWED_REDIRECT_URIS.includes(uri);
  return true; // no allowlist configured: rely on Entra's own redirect validation
}

// ---------------------------------------------------------------- discovery
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: PUBLIC_URL,
    authorization_endpoint: `${PUBLIC_URL}/authorize`,
    token_endpoint: `${PUBLIC_URL}/token`,
    registration_endpoint: `${PUBLIC_URL}/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: SCOPES.split(' '),
  });
});

app.get('/.well-known/oauth-protected-resource', (req, res) => {
  res.json({
    resource: `${PUBLIC_URL}/mcp`,
    authorization_servers: [PUBLIC_URL],
    bearer_methods_supported: ['header'],
    scopes_supported: SCOPES.split(' '),
  });
});

// ---------------------------------------------------------- dynamic register
app.post('/register', express.json(), (req, res) => {
  const body = req.body || {};
  res.status(201).json({
    client_id: `mcp-client-${Date.now()}`,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: body.redirect_uris || [],
    grant_types: body.grant_types || ['authorization_code', 'refresh_token'],
    response_types: body.response_types || ['code'],
    token_endpoint_auth_method: 'none',
    client_name: body.client_name || 'MCP Client',
  });
});

// ------------------------------------------------------------------ authorize
app.get('/authorize', (req, res) => {
  const q = req.query;
  const redirectUri = q.redirect_uri;
  if (!isAllowedRedirect(redirectUri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is not allowed' });
  }
  const msUrl = new URL(`${AUTHORITY}/oauth2/v2.0/authorize`);
  for (const p of ['response_type', 'redirect_uri', 'state', 'response_mode', 'prompt', 'login_hint', 'domain_hint']) {
    if (q[p]) msUrl.searchParams.set(p, q[p]);
  }
  // two-leg PKCE: keep client's challenge, mint our own for the server<->MS leg
  const clientChallenge = q.code_challenge;
  const state = q.state;
  if (clientChallenge && state) {
    gcPkce();
    if (pkceStore.size >= 1000) return res.status(503).json({ error: 'server_busy' });
    const serverVerifier = crypto.randomBytes(32).toString('base64url');
    const serverChallenge = crypto.createHash('sha256').update(serverVerifier).digest('base64url');
    pkceStore.set(state, { clientChallenge, serverVerifier, createdAt: Date.now() });
    msUrl.searchParams.set('code_challenge', serverChallenge);
    msUrl.searchParams.set('code_challenge_method', 'S256');
  } else if (clientChallenge) {
    msUrl.searchParams.set('code_challenge', clientChallenge);
    msUrl.searchParams.set('code_challenge_method', q.code_challenge_method || 'S256');
  }
  msUrl.searchParams.set('client_id', CLIENT_ID);
  const requested = q.scope ? q.scope.split(/\s+/).filter(Boolean) : [];
  const scopeSet = new Set([...requested, 'openid', 'profile', 'offline_access', 'User.Read']);
  msUrl.searchParams.set('scope', Array.from(scopeSet).join(' '));
  res.redirect(msUrl.toString());
});

// --------------------------------------------------------------------- token
async function entraToken(form) {
  const r = await fetch(`${AUTHORITY}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form),
  });
  const data = await r.json();
  return { ok: r.ok, status: r.status, data };
}

app.post('/token', express.urlencoded({ extended: true }), express.json(), async (req, res) => {
  const body = req.body || {};
  try {
    if (body.grant_type === 'authorization_code') {
      // match client's verifier against stored challenges to recover server verifier
      let serverVerifier;
      if (body.code_verifier) {
        const computed = crypto.createHash('sha256').update(body.code_verifier).digest('base64url');
        for (const [state, p] of pkceStore) {
          if (p.clientChallenge === computed) { serverVerifier = p.serverVerifier; pkceStore.delete(state); break; }
        }
      }
      const { ok, status, data } = await entraToken({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code: body.code,
        redirect_uri: body.redirect_uri,
        code_verifier: serverVerifier || body.code_verifier || '',
      });
      return res.status(ok ? 200 : status).json(data);
    }
    if (body.grant_type === 'refresh_token') {
      const { ok, status, data } = await entraToken({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: body.refresh_token,
        scope: SCOPES,
      });
      return res.status(ok ? 200 : status).json(data);
    }
    return res.status(400).json({ error: 'unsupported_grant_type' });
  } catch (e) {
    console.error('token error', e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ------------------------------------------------- bearer verification (cached)
const tokenCache = new Map(); // token -> expiresAt(ms)
async function verifyEntra(token) {
  const cached = tokenCache.get(token);
  if (cached && cached > Date.now()) return true;
  const r = await fetch('https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName', {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) return false;
  tokenCache.set(token, Date.now() + 5 * 60 * 1000); // 5 min cache
  if (tokenCache.size > 5000) for (const k of tokenCache.keys()) { tokenCache.delete(k); if (tokenCache.size <= 4000) break; }
  return true;
}

function unauthorized(res) {
  res.set('WWW-Authenticate',
    `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`);
  return res.status(401).json({ error: 'invalid_token' });
}

// ----------------------------------------------------- /mcp reverse proxy
const proxy = httpProxy.createProxyServer({
  target: UPSTREAM_BASE,
  changeOrigin: true,
  xfwd: true,
});
proxy.on('proxyReq', (proxyReq) => {
  // swap caller's Entra token for the upstream's static bearer
  proxyReq.setHeader('authorization', `Bearer ${UPSTREAM_JWT}`);
});
proxy.on('error', (err, _req, res) => {
  console.error('proxy error', err.message);
  if (res && !res.headersSent) res.status(502).json({ error: 'bad_gateway', detail: err.message });
});

async function mcpHandler(req, res) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return unauthorized(res);
  let ok = false;
  try { ok = await verifyEntra(m[1]); } catch (e) { console.error('verify error', e); }
  if (!ok) return unauthorized(res);
  proxy.web(req, res); // streams body + SSE response; path /mcp preserved
}
app.all('/mcp', mcpHandler);
app.all('/mcp/*', mcpHandler);

// -------------------------------------------------------------------- health
app.get('/', (_req, res) => res.json({ ok: true, service: 'pipedrive-mcp-oauth-proxy' }));

app.listen(PORT, () => {
  console.log(`oauth-proxy listening on :${PORT}`);
  console.log(`  issuer:   ${PUBLIC_URL}`);
  console.log(`  upstream: ${UPSTREAM_BASE}`);
});
