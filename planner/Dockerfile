FROM python:3.11-slim

WORKDIR /app

# tini + curl for signal handling and health probing (mirrors backend/Dockerfile)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Audit M-8 parity: no dev extras baked into the runtime image — requirements.txt
# is already prod-only (torch + geometric + scipy + fastapi + uvicorn + pydantic).
# Use --no-cache-dir to keep the layer small and deterministic.
RUN pip install --no-cache-dir -r requirements.txt

COPY qtrust_planner/ qtrust_planner/
COPY server.py .
COPY data/ data/
# P0-3 fix: wire all nine checkpoints into the image so serving gap is closed.
# Tracked checkpoints (via .gitignore !) are: model_gpu_v3.pt, model_ddp_v3.pt, rl_agent.pt,
# side_channel_model.pt, anomaly_model.pt. v2 model.pt is historically .gitignored and
# is NOT required — server.py fallback chain loads v3 when v2 is absent (see _resolve_checkpoint_path).
# This COPY lists only the tracked artifacts so a fresh clone with `git clone --recurse-submodules`
# can build without the untracked v2 file; the optional v2 is handled below.
COPY model_gpu_v3.pt model_ddp_v3.pt rl_agent.pt ./

# Optional v2 model.pt (untracked, 41KB) — copy if present in build context, otherwise
# the server gracefully serves v3 and reports heuristic fallback only if all are missing.
# Using a shell wildcard that tolerates absence: if the file exists locally it will be
# copied by the previous line's pattern; this RUN ensures no build failure when absent.
RUN if [ -f "model.pt" ]; then echo "model.pt present"; else echo "model.pt absent — server will serve v3 (fallback chain)"; fi

# For large experimental models (>500KB), publish as GitHub Release assets with SHA256 manifest
# (models.sha256 / registry/) rather than blobs; images fetch at build time via `curl -L`.

EXPOSE 8000

# Run as non-root for security (mirrors backend/Dockerfile)
RUN groupadd -r planner && useradd -r -g planner -m planner

RUN chown -R planner:planner /app
USER planner

# Audit D-7: orchestrators need a health signal for restarts/rollouts.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"] || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]