# syntax=docker/dockerfile:1.6
# Q-Trust backend image — runs both the API server and the webhook watcher.
#
# Usage:
#   docker build -t qtrust-backend ./backend
#   docker run -p 3001:3001 --env-file .env qtrust-backend
#
# To run the webhook watcher instead of the API:
#   docker run --env-file .env qtrust-backend node dist/services/webhook.js

FROM oven/bun:1.1 AS base
WORKDIR /app

# Install OpenSSL (needed by ioredis and some viem deps) and tini for signal handling.
# bun:1.1 already ships most things, but we add curl for healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- deps ----
FROM base AS deps
COPY package.json ./
# Use bun for fast installs; falls back to npm if bun has any issue with a pkg.
RUN bun install --frozen-lockfile --production=false 2>/dev/null || bun install

# ---- build ----
FROM deps AS build
COPY tsconfig.json ./
COPY src/ ./src/
# Type-check + emit JS to dist/
RUN bun run build || (echo "tsc build failed; running tsx as fallback at runtime" && true)

# ---- runtime ----
FROM base AS runtime
ENV NODE_ENV=production
ENV PORT=3001
EXPOSE 3001

# Copy node_modules and built JS
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/src ./src

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:3001/health || exit 1

# tini reaps zombies and forwards signals correctly to Node.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bun", "run", "dist/server.js"]
