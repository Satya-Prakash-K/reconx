#!/usr/bin/env bash
# ============================================
# ReconX — Ubuntu 22.04 LTS Setup Script
# ============================================
# Run: chmod +x scripts/setup.sh && ./scripts/setup.sh
#
# This script installs ALL dependencies needed to run ReconX
# on a fresh Ubuntu 22.04 LTS server/VM.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
header() { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

# ── System Update ────────────────────────────

header "System Update"
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y \
    curl wget git unzip build-essential pkg-config \
    libssl-dev cmake jq dnsutils net-tools \
    apt-transport-https ca-certificates gnupg lsb-release

# ── Docker ───────────────────────────────────

header "Installing Docker"
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER"
    log "Docker installed. You may need to re-login for group changes."
else
    log "Docker already installed"
fi

# Docker Compose (v2 plugin)
if ! docker compose version &>/dev/null; then
    sudo apt-get install -y docker-compose-plugin
fi
log "Docker Compose: $(docker compose version --short 2>/dev/null || echo 'installed')"

# ── Python 3.11+ ────────────────────────────

header "Installing Python 3.11"
if ! command -v python3.11 &>/dev/null; then
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt-get update
    sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
fi
log "Python: $(python3.11 --version)"

# ── Rust ─────────────────────────────────────

header "Installing Rust"
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
log "Rust: $(rustc --version)"

# ── Node.js 20 ──────────────────────────────

header "Installing Node.js 20"
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
log "Node: $(node --version)"
log "npm: $(npm --version)"

# ── Go (for recon tools) ────────────────────

header "Installing Go"
if ! command -v go &>/dev/null; then
    GO_VERSION="1.22.2"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi
log "Go: $(go version)"

# ── Recon Tools ──────────────────────────────

header "Installing Recon Tools"

install_go_tool() {
    local name=$1 pkg=$2
    if ! command -v "$name" &>/dev/null; then
        log "Installing $name..."
        go install "$pkg" 2>/dev/null || warn "Failed to install $name"
    else
        log "$name already installed"
    fi
}

# ProjectDiscovery tools
install_go_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool dnsx "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool naabu "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool katana "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool nuclei "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# Other tools
install_go_tool assetfinder "github.com/tomnomnom/assetfinder@latest"
install_go_tool waybackurls "github.com/tomnomnom/waybackurls@latest"
install_go_tool gau "github.com/lc/gau/v2/cmd/gau@latest"
install_go_tool hakrawler "github.com/hakluke/hakrawler@latest"

# Findomain
if ! command -v findomain &>/dev/null; then
    log "Installing findomain..."
    wget -q "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip"
    unzip -o findomain-linux.zip -d /tmp/
    sudo mv /tmp/findomain /usr/local/bin/
    sudo chmod +x /usr/local/bin/findomain
    rm -f findomain-linux.zip
fi

# Masscan
if ! command -v masscan &>/dev/null; then
    log "Installing masscan..."
    sudo apt-get install -y masscan
fi

# Nmap
if ! command -v nmap &>/dev/null; then
    log "Installing nmap..."
    sudo apt-get install -y nmap
fi

# MassDNS
if ! command -v massdns &>/dev/null; then
    log "Installing massdns..."
    git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
    cd /tmp/massdns && make && sudo make install
    cd - && rm -rf /tmp/massdns
fi

log "Recon tools installation complete"

# ── Kubectl (optional) ──────────────────────

header "Installing kubectl (optional)"
if ! command -v kubectl &>/dev/null; then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    rm kubectl
fi

# ── Terraform (optional) ────────────────────

header "Installing Terraform (optional)"
if ! command -v terraform &>/dev/null; then
    wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
        sudo tee /etc/apt/sources.list.d/hashicorp.list
    sudo apt-get update && sudo apt-get install -y terraform
fi

# ── Setup ReconX ─────────────────────────────

header "Setting Up ReconX"

# Copy env file
if [ ! -f .env ]; then
    cp .env.example .env
    warn "Created .env from template — please edit with your settings"
fi

# Create Python venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip

# Install shared library
pip install -e libs/shared-python

# Install service dependencies
pip install -e "apps/api-gateway[dev]"
pip install -e "apps/ai-engine[dev]"
pip install -e "apps/worker[dev]"

# Install frontend
cd apps/web
npm install
cd ../..

# Build Rust engine
cd apps/recon-engine
cargo build --release
cd ../..

header "Setup Complete!"
echo ""
log "ReconX is ready to run!"
echo ""
echo "  Quick start with Docker:"
echo "    cd infra/docker"
echo "    docker compose --profile core up -d"
echo ""
echo "  Development mode:"
echo "    source .venv/bin/activate"
echo "    cd apps/api-gateway && uvicorn src.main:app --reload"
echo ""
echo "  Frontend:"
echo "    cd apps/web && npm run dev"
echo ""
echo "  Access:"
echo "    Dashboard:  http://localhost:3000"
echo "    API:        http://localhost:8000"
echo "    API Docs:   http://localhost:8000/docs"
echo "    Grafana:    http://localhost:3001"
echo ""
