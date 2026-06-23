# Secrets — bor i Infisical, ikke i .env

**Source of truth for ALLE secrets er self-hosted Infisical:** `https://infisical.sliplane.app`,
projekt `true-collective` (id `33338719-29b2-4069-9a39-54b0ab851ec9`), environment `prod`.
Hver service har sin egen folder (se `INFISICAL_PATH` i platform-env).

## NEVER
- Hardkod aldrig en secret i kode, Dockerfile, config eller markdown.
- Commit aldrig en `.env` med rigtige værdier (kun `.env.example` med tomme `KEY=`).
- Læg aldrig en secret direkte i Sliplane/platform-env. Det ENESTE der må stå i platform-env
  er Infisical-bootstrap-vars (nedenfor) + ikke-hemmelig config (porte, URLs, feature-flags).

## ALWAYS — sådan henter servicen secrets
1. Servicen har en **machine identity** (Universal Auth) i Infisical med read-adgang til sin folder.
2. Platform-env indeholder KUN: `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` (secret),
   `INFISICAL_API_URL` (`https://infisical.sliplane.app/api`), `INFISICAL_PROJECT_ID`,
   `INFISICAL_ENV=prod`, `INFISICAL_PATH=/<denne-service>`.
3. Containeren starter via `infisical-entrypoint.sh` (logger ind + `infisical run` injicerer
   secrets som env-vars). Appen er Infisical-uvidende.

## Lokal udvikling
`brew install infisical/get-cli/infisical`, så:
`infisical run --projectId=33338719-29b2-4069-9a39-54b0ab851ec9 --env=prod \
  --domain=https://infisical.sliplane.app/api --path=/<service> -- <start-kommando>`

## Ny secret?
Tilføj den i Infisical i servicens folder — IKKE i `.env` eller platform-env.
Tilgængelig ved næste deploy/genstart.
