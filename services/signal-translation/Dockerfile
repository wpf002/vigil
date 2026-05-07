FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY services/signal-translation/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/signal-translation /app/services/signal-translation
COPY detections /app/detections
WORKDIR /app/services/signal-translation
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8004/health || exit 1
EXPOSE 8004
CMD ["python", "run.py"]
