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
# Lean runtime image: only production dependencies + the built dist/ output.
FROM node:20-alpine AS production
WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

# Dashboard/API port + SSH, Telnet, HTTP decoy listeners
EXPOSE 3000 2222 2323 8080

# Run as the unprivileged 'node' user, per the README's sandboxing guidance.
RUN chown -R node:node /app
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/settings || exit 1

CMD ["node", "dist/server.cjs"]
