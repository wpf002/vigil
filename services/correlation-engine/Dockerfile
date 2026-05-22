FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Sibling services that the correlation engine bridges via _compat.py.
# Build context expected to be the repo root (services/).
COPY services/correlation-engine/requirements.txt ./correlation-engine/requirements.txt
COPY services/attack-state-engine/requirements.txt ./attack-state-engine/requirements.txt
COPY services/ingestor/requirements.txt ./ingestor/requirements.txt
RUN pip install --no-cache-dir \
        -r ./correlation-engine/requirements.txt \
        -r ./attack-state-engine/requirements.txt \
        -r ./ingestor/requirements.txt

COPY services/correlation-engine /app/correlation-engine
COPY services/attack-state-engine /app/attack-state-engine
COPY services/ingestor /app/ingestor

WORKDIR /app/correlation-engine
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1
EXPOSE 8003
CMD ["python", "run.py"]
