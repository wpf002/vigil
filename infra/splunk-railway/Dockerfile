# VIGIL Splunk instance for Railway (always-on SIEM the ingestor polls).
#
# Bakes the VIGIL config as a Splunk app so it survives redeploys:
#   - index `vigil_test`
#   - IPv6 listener (Railway's private network is IPv6-only) + remote REST login
# HEC token + admin password come from env (SPLUNK_HEC_TOKEN / SPLUNK_PASSWORD).
# Indexed data lives on a Railway volume at /opt/splunk/var — REQUIRED: Splunk's
# validatedb rejects the container overlay fs as "unusable", so the index path
# must be on a volume (real ext4) or splunkd refuses to start.
FROM splunk/splunk:9.2

COPY --chown=splunk:splunk etc-apps/vigil /opt/splunk/etc/apps/vigil

# --accept-license so the container starts unattended (60-day Enterprise trial,
# then Splunk Free — we poll the index directly so alerting isn't required).
ENV SPLUNK_START_ARGS=--accept-license

EXPOSE 8000 8088 8089
