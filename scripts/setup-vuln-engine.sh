#!/usr/bin/env bash
# ============================================
# ReconX — Vulnerability Engine Setup (Ubuntu)
# ============================================
# Run AFTER scripts/setup.sh
# Installs vuln-specific tools and dependencies

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
header() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

header "ReconX Vulnerability Engine Setup"

# ── Python Vuln Engine Dependencies ─────────

header "Installing Vuln Engine Python deps"
source .venv/bin/activate
pip install -e "apps/vuln-engine[dev]"

# ── Playwright Browsers ────────────────────

header "Installing Playwright Browsers"
pip install playwright
playwright install chromium --with-deps
log "Playwright + Chromium installed"

# ── Vuln Testing Tools ─────────────────────

header "Installing Vulnerability Testing Tools"

# Dalfox — XSS scanner
if ! command -v dalfox &>/dev/null; then
    log "Installing dalfox..."
    go install github.com/hahwul/dalfox/v2@latest
fi

# XSStrike — XSS scanner
if [ ! -d "/opt/xsstrike" ]; then
    log "Installing XSStrike..."
    sudo git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike
    sudo pip3 install -r /opt/xsstrike/requirements.txt
fi

# sqlmap — SQL Injection
if ! command -v sqlmap &>/dev/null; then
    log "Installing sqlmap..."
    sudo apt-get install -y sqlmap
fi

# ffuf — Web fuzzer
if ! command -v ffuf &>/dev/null; then
    log "Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest
fi

# Nuclei — Template scanner (may already be installed from setup.sh)
if ! command -v nuclei &>/dev/null; then
    log "Installing nuclei..."
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi

# Update nuclei templates
log "Updating nuclei templates..."
nuclei -update-templates 2>/dev/null || true

# Wordlists
header "Installing Wordlists"
if [ ! -d "/usr/share/wordlists" ]; then
    sudo mkdir -p /usr/share/wordlists
fi
if [ ! -f "/usr/share/wordlists/dirb/common.txt" ]; then
    sudo apt-get install -y dirb
fi
if [ ! -d "/usr/share/wordlists/SecLists" ]; then
    log "Installing SecLists..."
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
fi

# ── Ray Cluster ────────────────────────────

header "Installing Ray"
pip install "ray[default]>=2.9.0"
log "Ray installed: $(ray --version 2>/dev/null || echo 'installed')"

# ── Docker Vuln Profile ────────────────────

header "Starting Vuln Engine Services"
cd infra/docker

# Pull images
docker compose --profile vuln pull 2>/dev/null || true

# Start vuln profile (includes Ray, Selenium Grid, vuln-engine)
docker compose --profile vuln --profile ai up -d

# Wait for services
sleep 15

# Health check
log "Checking vuln-engine health..."
curl -sf http://localhost:8002/health && log "Vuln Engine: HEALTHY" || warn "Vuln Engine: Not ready yet"

cd ../..

header "Vuln Engine Setup Complete!"
echo ""
echo "  Services:"
echo "    Vuln Engine API:   http://localhost:8002"
echo "    Vuln Engine Docs:  http://localhost:8002/docs"
echo "    Ray Dashboard:     http://localhost:8265"
echo "    Selenium Grid:     http://localhost:4444"
echo ""
echo "  Launch a vuln scan:"
echo '    curl -X POST http://localhost:8002/api/v1/vuln/scans/start \'
echo '      -H "Content-Type: application/json" \'
echo '      -d '"'"'{"workspace_id":"test","target_urls":["https://target.com"]}'"'"''
echo ""
echo "  Full stack (all profiles):"
echo "    cd infra/docker && docker compose --profile all up -d"
echo ""
