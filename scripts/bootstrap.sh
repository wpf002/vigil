#!/usr/bin/env bash
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ██╗   ██╗██╗ ██████╗ ██╗██╗     "
echo "  ██║   ██║██║██╔════╝ ██║██║     "
echo "  ██║   ██║██║██║  ███╗██║██║     "
echo "  ╚██╗ ██╔╝██║██║   ██║██║██║     "
echo "   ╚████╔╝ ██║╚██████╔╝██║███████╗"
echo "    ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${CYAN}AI-Native Security Operations Platform${NC}"
echo ""

check_command() {
  if ! command -v "$1" &> /dev/null; then
    echo -e "${RED}✗ $1 not found. Please install before continuing.${NC}"
    exit 1
  else
    echo -e "${GREEN}✓ $1${NC}"
  fi
}

echo -e "${YELLOW}Checking prerequisites...${NC}"
check_command python3
check_command node
check_command npm
check_command docker
check_command git
echo ""

# Python venvs
echo -e "${YELLOW}Creating Python virtual environments...${NC}"
PYTHON_SERVICES=("api" "ingestor" "attack-state-engine" "correlation-engine" "signal-translation" "detection-engine" "ai-engine" "playbook-engine" "analyst-portal")
for svc in "${PYTHON_SERVICES[@]}"; do
  if [ -d "services/$svc" ]; then
    python3 -m venv "services/$svc/.venv"
    echo -e "${GREEN}✓ services/$svc/.venv${NC}"
  fi
done
echo ""

# Copy .env files
echo -e "${YELLOW}Copying .env.example files...${NC}"
for svc in "${PYTHON_SERVICES[@]}"; do
  if [ -f "services/$svc/.env.example" ] && [ ! -f "services/$svc/.env" ]; then
    cp "services/$svc/.env.example" "services/$svc/.env"
    echo -e "${GREEN}✓ services/$svc/.env${NC}"
  fi
done
echo ""

# Frontend
echo -e "${YELLOW}Installing frontend dependencies...${NC}"
if [ -d "frontend" ]; then
  cd frontend && npm install && cd ..
  echo -e "${GREEN}✓ frontend/node_modules${NC}"
fi
echo ""

# Git init
if [ ! -d ".git" ]; then
  echo -e "${YELLOW}Initializing git repository...${NC}"
  git init
  git add .
  git commit -m "feat: initial VIGIL platform scaffold"
  echo -e "${GREEN}✓ git initialized${NC}"
  echo ""
fi

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Bootstrap complete.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${CYAN}1. Open workspace:${NC}  code vigil.code-workspace"
echo -e "  ${CYAN}2. Start infra:${NC}     docker-compose up -d"
echo -e "  ${CYAN}3. Configure:${NC}       edit services/*/.env with your Splunk creds"
echo -e "  ${CYAN}4. Push to GitHub:${NC}"
echo -e "     git remote add origin https://github.com/YOUR_USERNAME/vigil.git"
echo -e "     git push -u origin main"
echo ""
