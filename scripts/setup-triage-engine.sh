#!/usr/bin/env bash
# ============================================
# ReconX — Triage & Report Engine Setup (Ubuntu)
# ============================================
# Run AFTER scripts/setup.sh and scripts/setup-vuln-engine.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
header() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

header "ReconX Triage & Report Engine Setup"

# ── Python Dependencies ────────────────────

header "Installing Triage Engine Python deps"
source .venv/bin/activate
pip install -e "apps/triage-engine[dev]"

# ── Sentence Transformers (embedding model) ─

header "Pre-loading Embedding Model"
python -c "
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')
print(f'Model loaded: {model.get_sentence_embedding_dimension()} dimensions')
" && log "Embedding model cached" || warn "Embedding model will be downloaded on first use"

# ── WeasyPrint (PDF generation) ─────────────

header "Installing WeasyPrint system deps"
sudo apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev shared-mime-info
log "WeasyPrint deps installed"

# ── Docker Triage Profile ──────────────────

header "Starting Triage Engine Services"
cd infra/docker

# Pull images
docker compose --profile triage pull 2>/dev/null || true

# Start triage profile (requires AI services for LLM and Qdrant)
docker compose --profile triage --profile ai up -d

# Wait for services
sleep 15

# Health checks
log "Checking triage-engine health..."
curl -sf http://localhost:8003/health && log "Triage Engine: HEALTHY" || warn "Triage Engine: Starting..."

log "Checking Qdrant..."
curl -sf http://localhost:6333/healthz && log "Qdrant: HEALTHY" || warn "Qdrant: Starting..."

log "Checking Neo4j..."
curl -sf http://localhost:7474 && log "Neo4j: HEALTHY" || warn "Neo4j: Starting..."

log "Checking Elasticsearch..."
curl -sf http://localhost:9200/_cluster/health && log "Elasticsearch: HEALTHY" || warn "ES: Starting..."

cd ../..

header "Triage Engine Setup Complete!"
echo ""
echo "  Services:"
echo "    Triage Engine API:     http://localhost:8003"
echo "    Triage Engine Docs:    http://localhost:8003/docs"
echo "    Qdrant Dashboard:      http://localhost:6333/dashboard"
echo "    Neo4j Browser:         http://localhost:7474"
echo "    Elasticsearch:         http://localhost:9200"
echo ""
echo "  Triage a batch of findings:"
echo '    curl -X POST http://localhost:8003/api/v1/triage/batch \'
echo '      -H "Content-Type: application/json" \'
echo '      -d '"'"'{"workspace_id":"test","findings":[{"title":"SQLi","category":"sqli","affected_url":"https://t.com","confidence":0.9}]}'"'"''
echo ""
echo "  Generate a report:"
echo '    curl -X POST http://localhost:8003/api/v1/reports/generate \'
echo '      -H "Content-Type: application/json" \'
echo '      -d '"'"'{"finding":{"title":"SQLi","category":"sqli","severity":"critical","affected_url":"https://t.com"},"format":"hackerone"}'"'"''
echo ""
echo "  Full stack deployment:"
echo "    cd infra/docker && docker compose --profile all up -d"
echo ""
