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

FROM oven/bun:1.1 AS base
WORKDIR /app

# Install OpenSSL (needed by ioredis and some viem deps) and tini for signal handling.
# bun:1.1 already ships most things, but we add curl for healthchecks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- deps ----
# Audit M-8: two dep trees — full (with devDependencies) for the build stage,
# production-only for the runtime image so dev-only binaries (tsx/esbuild,
# vitest workers) are not shipped to production.
FROM base AS deps
COPY backend/package.json ./
# Use bun for fast installs; falls back to npm if bun has any issue with a pkg.
RUN bun install --frozen-lockfile --production=false 2>/dev/null || bun install

# ---- prod-deps ----
FROM base AS prod-deps
COPY backend/package.json ./
RUN bun install --frozen-lockfile --production 2>/dev/null || bun install --production

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
    && apt-get install -y --no-install-recommends python3 python3-pip python3-venv wget \
    && rm -rf /var/lib/apt/lists/*

# Install the inspector into a dedicated venv so `QTRUST_INSPECTOR_PYTHON`
# resolves for any user (including the non-root runtime user below) without
# violating PEP 668 via --break-system-packages.
COPY inspector/ /inspector/
RUN python3 -m venv /opt/inspector-venv \
    && /opt/inspector-venv/bin/pip install --no-cache-dir /inspector \
    && rm -rf /inspector

EXPOSE 3001

ENV QTRUST_INSPECTOR_PYTHON=/opt/inspector-venv/bin/python3

# Run as non-root for security
RUN groupadd -r qtrust && useradd -r -g qtrust -m qtrust

# Audit L-9: create + chown the default evidence-chain directory so the
# non-root runtime user can persist /var/lib/qtrust/evidence_chain.jsonl
# (previously mkdir failed with EACCES and the chain silently degraded to
# in-memory only, losing all evidence on restart).
RUN mkdir -p /var/lib/qtrust && chown qtrust:qtrust /var/lib/qtrust

# Copy PRODUCTION node_modules and built JS only — no devDependencies in the
# runtime image (audit M-8), no source code.
COPY --from=prod-deps /app/node_modules ./node_modules
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
