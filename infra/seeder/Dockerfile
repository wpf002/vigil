# One-shot seeder: runs scripts/seed_demo.py inside the Railway network so it
# can reach the private Kafka (kafka.railway.internal). Publishes synthetic CDM
# events to vigil.signals.raw under TENANT_ID; the correlation engine turns them
# into AttackStates. Build context = repo root.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir kafka-python-ng==2.2.3 pydantic==2.7.1 pydantic-settings==2.3.0
COPY scripts /app/scripts
COPY services/ingestor /app/services/ingestor
CMD ["python", "scripts/seed_demo.py"]
