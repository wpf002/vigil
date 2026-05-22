#!/bin/sh
# Railway wrapper for temporalio/auto-setup.
#
# Temporal's ringpop membership requires a literal IP for `broadcastAddress`
# whenever the server binds all interfaces (BIND_ON_IP=0.0.0.0). Railway assigns
# the container's private IP per-deploy, so resolve it at runtime and export it
# as TEMPORAL_BROADCAST_ADDRESS before handing off to the stock entrypoint.
set -e

# Prefer the private IPv4 (10.x) that *.railway.internal resolves to; fall back
# to whatever `hostname -i` reports.
IP="$(getent ahostsv4 "$RAILWAY_PRIVATE_DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')"
if [ -z "$IP" ]; then
  IP="$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)"
fi
if [ -z "$IP" ]; then
  # Last resort: first address hostname -i prints (may be IPv6).
  IP="$(hostname -i 2>/dev/null | awk '{print $1}')"
fi

export TEMPORAL_BROADCAST_ADDRESS="$IP"
echo "[railway-temporal] resolved private IP -> TEMPORAL_BROADCAST_ADDRESS=$IP (BIND_ON_IP=${BIND_ON_IP:-unset})"

exec /etc/temporal/entrypoint.sh autosetup
