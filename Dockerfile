# ---- Build stage ----
# Installs full dependencies (incl. devDependencies) and builds the frontend
# (vite build -> dist/) plus the bundled server (esbuild -> dist/server.cjs).
FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- Production stage ----
# Debian-based (not Alpine): Prowler's dependencies (lz4, zstd, etc.) ship
# prebuilt manylinux/glibc wheels. Alpine's musl libc has no matching prebuilt
# wheels, so pip falls back to compiling from source and fails with no C
# compiler present. Debian-slim avoids that entirely.
FROM node:20-bookworm-slim AS production
WORKDIR /app
ENV NODE_ENV=production

# Python + Prowler CLI, used by POST /api/prowler/scan to run real on-demand
# Azure scans (via an Azure Service Principal - see .env.example).
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/prowler-venv && \
    /opt/prowler-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/prowler-venv/bin/pip install --no-cache-dir prowler
ENV PROWLER_BIN=/opt/prowler-venv/bin/prowler

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

# Dashboard/API port + SSH, Telnet, HTTP decoy listeners
EXPOSE 3000 2222 2323 8080

# Run as the unprivileged 'node' user, per the README's sandboxing guidance.
RUN chown -R node:node /app
USER node

# Debian-slim doesn't ship wget/curl by default, so use Node itself to probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/settings', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"

CMD ["node", "dist/server.cjs"]
