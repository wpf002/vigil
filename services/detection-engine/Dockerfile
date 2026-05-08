FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Build context is the repo root (see docker-compose.yml) so we can bake
# detections/ into the image alongside the service code. This makes the
# manifest sync independent of bind-mount timing on macOS.
COPY services/detection-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/detection-engine/ /app/
COPY detections/ /app/detections/

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8005/health || exit 1
EXPOSE 8005
CMD ["python", "run.py"]
