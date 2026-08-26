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

# model.pt is .gitignored — fetch from GitHub release or build locally:
#   python -m qtrust_planner.train && cp planner/model.pt planner/model.pt
# No placeholder model is generated here: an empty state_dict would silently
# serve untrained GNN outputs. With model.pt absent, server.py starts in
# heuristic mode and says so in /health and structured logs.

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