FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
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

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]