#!/usr/bin/env bash
#
# dev.sh — start VIGIL's host-run services for local development.
#
# Docker compose runs infra + the containerized services (api, ingestor,
# detection-engine, ai-engine, playbook-engine, analyst-portal, reporting,
# signal-translation, vigil-osint). A few services run on the HOST in their
# own venvs via run.py (which aliases the hyphenated dirs as importable
# packages). This script launches those host services and tails their logs.
#
# Usage:  bash dev.sh            # start infra (compose) + host services
#         bash dev.sh --host     # host services only (compose already up)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

# port → service dir (host-run services).
declare -a HOST_SERVICES=(
  "8002:attack-state-engine"
  "8003:correlation-engine"
  "8012:vigil-osint"
)

AUTH_SECRET="${AUTH_SECRET:-dev-only-secret-change-me}"
ENVIRONMENT="${ENVIRONMENT:-development}"
export AUTH_SECRET ENVIRONMENT

if [[ "${1:-}" != "--host" ]]; then
  echo -e "${YELLOW}Starting infra + containerized services (docker compose)...${NC}"
  docker compose up -d
  echo ""
fi

mkdir -p .dev-logs
echo -e "${YELLOW}Starting host services...${NC}"
for entry in "${HOST_SERVICES[@]}"; do
  port="${entry%%:*}"; svc="${entry##*:}"
  dir="services/$svc"
  [[ -d "$dir" ]] || { echo -e "${YELLOW}  skip $svc (missing)${NC}"; continue; }

  # Create the venv on first run so a fresh checkout works.
  if [[ ! -d "$dir/.venv" ]]; then
    echo -e "${CYAN}  creating venv for $svc...${NC}"
    python3 -m venv "$dir/.venv"
    "$dir/.venv/bin/pip" install -q -r "$dir/requirements.txt"
  fi

  ( cd "$dir" && PORT="$port" .venv/bin/python run.py ) > ".dev-logs/$svc.log" 2>&1 &
  echo -e "${GREEN}  ✓ $svc on :$port (logs: .dev-logs/$svc.log)${NC}"
done

echo ""
echo -e "${GREEN}Host services started.${NC} Frontend: ${CYAN}cd frontend && npm run dev${NC} (Vite :5173)"
echo -e "vigil-osint health: ${CYAN}curl localhost:8012/health${NC}"
echo -e "Stop host services: ${CYAN}pkill -f run.py${NC}"
