#!/usr/bin/env bash
# ============================================
# ReconX v2 — Autonomous Engine Setup (Ubuntu)
# ============================================
# Run AFTER setup.sh, setup-vuln-engine.sh, setup-triage-engine.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
header() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

header "ReconX v2: Autonomous Engine Setup"

# ── Python Dependencies ────────────────────

header "Installing Autonomous Engine Python deps"
source .venv/bin/activate
pip install -e "apps/autonomous-engine[dev]"

# ── Playwright for Browser Automation ──────

header "Installing Playwright browsers"
playwright install chromium --with-deps
log "Playwright Chromium installed"

# ── CLI Tool ───────────────────────────────

header "Installing ReconX CLI"
pip install -e apps/autonomous-engine
log "CLI installed — run 'reconx --help' to verify"

# ── ClickHouse ─────────────────────────────

header "Setting up ClickHouse"
if command -v clickhouse-client &>/dev/null; then
    log "ClickHouse client already installed"
else
    sudo apt-get install -y --no-install-recommends clickhouse-client
fi

# ── Istio (if K8s cluster available) ───────

header "Istio Service Mesh (optional)"
if command -v kubectl &>/dev/null; then
    if ! command -v istioctl &>/dev/null; then
        curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.20.0 sh -
        sudo mv istio-*/bin/istioctl /usr/local/bin/
        rm -rf istio-*
        log "Istio CLI installed"
    fi
    warn "Run 'istioctl install --set profile=demo -y' to install Istio on your cluster"
else
    warn "kubectl not found — skipping Istio setup"
fi

# ── ArgoCD (if K8s cluster available) ──────

if command -v kubectl &>/dev/null; then
    warn "Install ArgoCD: kubectl create namespace argocd && kubectl apply -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml -n argocd"
fi

# ── Docker Services ───────────────────────

header "Starting All Services"
cd infra/docker

docker compose --profile all pull 2>/dev/null || true
docker compose --profile all up -d

sleep 20

# Health checks
log "Checking autonomous-engine..."
curl -sf http://localhost:8004/health && log "Autonomous Engine: HEALTHY" || warn "Starting..."

log "Checking clickhouse..."
curl -sf "http://localhost:8123/?query=SELECT%201" && log "ClickHouse: HEALTHY" || warn "Starting..."

log "Checking triage-engine..."
curl -sf http://localhost:8003/health && log "Triage Engine: HEALTHY" || warn "Starting..."

log "Checking vuln-engine..."
curl -sf http://localhost:8002/health && log "Vuln Engine: HEALTHY" || warn "Starting..."

cd ../..

header "ReconX v2 Setup Complete!"
echo ""
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║           ReconX v2 — Autonomous Security Platform          ║"
echo "  ╠══════════════════════════════════════════════════════════════╣"
echo "  ║ Service                │ URL                                ║"
echo "  ║────────────────────────┼────────────────────────────────────║"
echo "  ║ API Gateway            │ http://localhost:8000              ║"
echo "  ║ Vuln Engine            │ http://localhost:8002              ║"
echo "  ║ Triage Engine          │ http://localhost:8003              ║"
echo "  ║ Autonomous Engine      │ http://localhost:8004              ║"
echo "  ║ Web Dashboard          │ http://localhost:3000              ║"
echo "  ║ ClickHouse             │ http://localhost:8123              ║"
echo "  ║ Ray Dashboard          │ http://localhost:8265              ║"
echo "  ║ Selenium Grid          │ http://localhost:4444              ║"
echo "  ║ Neo4j Browser          │ http://localhost:7474              ║"
echo "  ║ Qdrant Dashboard       │ http://localhost:6333/dashboard    ║"
echo "  ║ Grafana                │ http://localhost:3001              ║"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  CLI Quick Start:"
echo "    reconx scan --target https://your-authorized-target.com --mode autonomous"
echo "    reconx triage --workspace test-ws --file findings.json"
echo "    reconx report --finding '{\"title\":\"SQLi\",\"category\":\"sqli\"}' --format hackerone"
echo "    reconx monitor --target https://your-target.com --interval 3600"
echo "    reconx intel --category sqli"
echo "    reconx status"
echo ""
echo "  Kubernetes:"
echo "    kubectl apply -k infra/k8s/"
echo "    istioctl install --set profile=demo -y"
echo "    kubectl apply -f infra/argocd/application.yml"
echo ""
