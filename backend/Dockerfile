# syntax=docker/dockerfile:1.6
# Q-Trust backend image — runs both the API server and the webhook watcher.
#
# IMPORTANT: build context must be the repository root (the image bundles the
# Python inspector package):
#   docker build -f backend/Dockerfile -t qtrust-backend .
#   docker run -p 3001:3001 --env-file .env qtrust-backend
#
# To run the webhook watcher instead of the API:
#   docker run --env-file .env qtrust-backend node dist/services/webhook.js

FROM oven/bun:1.3 AS base
WORKDIR /app

# Install OpenSSL (needed by ioredis and some viem deps) and tini for signal handling.
# bun:1.1 already ships most things, but we add curl for healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- deps ----
FROM base AS deps
COPY backend/package.json ./
# Use bun for fast installs; falls back to npm if bun has any issue with a pkg.
RUN bun install --frozen-lockfile --production=false 2>/dev/null || bun install

# ---- build ----
FROM deps AS build
COPY backend/tsconfig.json ./
COPY backend/src/ ./src/
# Type-check + emit JS to dist/ — fail hard on build errors
RUN bun run build

# ---- runtime ----
FROM base AS runtime
ENV NODE_ENV=production
ENV PORT=3001

# python3 runs the cryptographic inspector shelled out to by /v1/scan/* routes;
# wget is a dependency-free healthcheck fallback alongside curl.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip wget \
    && rm -rf /var/lib/apt/lists/*

# Install the inspector into site-packages so `python3 -m`-style imports resolve
# for any user (including the non-root runtime user below).
COPY inspector/ /inspector/
RUN pip3 install --break-system-packages --no-cache-dir /inspector \
        || pip3 install --no-cache-dir /inspector \
    && rm -rf /inspector

EXPOSE 3001

ENV QTRUST_INSPECTOR_PYTHON=python3

# Run as non-root for security
RUN groupadd -r qtrust && useradd -r -g qtrust -m qtrust

# Copy node_modules and built JS only (no source code in runtime image)
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
COPY backend/scripts/run_inspector.py ./scripts/run_inspector.py

RUN chown -R qtrust:qtrust /app
USER qtrust

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:3001/v1/health || exit 1

# tini reaps zombies and forwards signals correctly to Node.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bun", "run", "dist/server.js"]
