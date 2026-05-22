# Railway-friendly Temporal: wraps temporalio/auto-setup so ringpop gets a
# literal broadcast IP (resolved at runtime) instead of a hostname.
FROM temporalio/auto-setup:1.24.2
COPY entrypoint.sh /railway-temporal-entrypoint.sh
USER root
RUN chmod +x /railway-temporal-entrypoint.sh
ENTRYPOINT ["/railway-temporal-entrypoint.sh"]
