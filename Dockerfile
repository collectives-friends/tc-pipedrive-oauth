FROM node:24-alpine
WORKDIR /app
# Infisical CLI — secrets injected from the vault at runtime
RUN apk add --no-cache wget ca-certificates && \
    ARCH=$(uname -m); case "$ARCH" in x86_64) A=amd64;; aarch64) A=arm64;; *) A=amd64;; esac; \
    wget -qO /tmp/inf.tar.gz "https://github.com/Infisical/cli/releases/download/v0.43.96/cli_0.43.96_linux_${A}.tar.gz" && \
    tar -xzf /tmp/inf.tar.gz -C /usr/local/bin infisical && \
    rm /tmp/inf.tar.gz && chmod +x /usr/local/bin/infisical
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
COPY infisical-entrypoint.sh /app/infisical-entrypoint.sh
RUN chmod +x /app/infisical-entrypoint.sh
ENV NODE_ENV=production
EXPOSE 3000
ENTRYPOINT ["/app/infisical-entrypoint.sh"]
