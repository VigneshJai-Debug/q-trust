FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY qtrust_planner/ qtrust_planner/
COPY server.py .
COPY data/ data/

# model.pt is .gitignored — fetch from GitHub release or build locally.
# If building locally, run: python -m qtrust_planner.train && cp planner/model.pt .
# For CI/docker, we generate a minimal model at build time if missing.
RUN if [ ! -f model.pt ]; then \
      echo "model.pt not found — generating minimal placeholder model"; \
      python -c "import torch; torch.save({'state_dict': {}}, 'model.pt')"; \
    fi

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]