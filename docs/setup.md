# ReconX Setup Guide

## VM Recommendation: **Ubuntu 22.04 LTS Server**

### Why Ubuntu 22.04 over Kali Linux?

| Factor | Ubuntu 22.04 LTS | Kali Linux |
|--------|------------------|------------|
| **Stability** | ✅ LTS — 5yr support | ⚠️ Rolling release |
| **Docker support** | ✅ Native, well-tested | ⚠️ Works but less tested |
| **Production use** | ✅ Designed for servers | ❌ Designed for pentesting desktops |
| **K8s support** | ✅ Official support | ⚠️ Possible but unsupported |
| **Security updates** | ✅ Canonical-backed | ⚠️ Community-driven |
| **Recon tools** | 🔧 Installed via script | ✅ Pre-installed |
| **Resource usage** | ✅ Minimal (headless) | ⚠️ Heavier (desktop env) |

> **Recommendation**: Use **Ubuntu 22.04 LTS Server** for running ReconX. Our setup script installs all necessary recon tools. Kali's pre-installed tools are convenient for manual testing but Ubuntu is far better for running a containerized platform.

---

## Minimum Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16+ GB |
| **Disk** | 50 GB | 100+ GB SSD |
| **OS** | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| **Network** | Outbound internet | Outbound internet |

For AI features (Ollama local LLM):
- **GPU**: NVIDIA GPU with 8GB+ VRAM (optional)
- **RAM**: Additional 8GB for model loading

---

## Quick Start (Ubuntu VM)

### 1. Transfer Files to VM

```bash
# Option A: SCP from your Windows machine
scp -r D:\Recon user@your-vm-ip:~/reconx

# Option B: Git clone (if pushed to repo)
git clone https://github.com/your-org/reconx.git ~/reconx

# Option C: rsync
rsync -avz D:\Recon/ user@your-vm-ip:~/reconx/
```

### 2. Run Setup Script

```bash
cd ~/reconx
chmod +x scripts/setup.sh
./scripts/setup.sh
```

This automatically installs:
- Docker & Docker Compose
- Python 3.11
- Rust toolchain
- Node.js 20
- Go 1.22
- All recon tools (subfinder, httpx, naabu, katana, etc.)
- kubectl, terraform
- Python virtual environment with all dependencies

### 3. Configure Environment

```bash
cp .env.example .env
nano .env  # Edit with your settings
```

Key settings to configure:
- `RECONX_SECRET_KEY` — Generate: `openssl rand -hex 32`
- `RECONX_ENCRYPTION_KEY` — Generate: `openssl rand -hex 32`
- `JWT_SECRET_KEY` — Generate: `openssl rand -hex 32`
- `POSTGRES_PASSWORD` — Strong password
- Database credentials

### 4. Start with Docker Compose

```bash
cd infra/docker

# Start core services (databases + app)
docker compose --profile core up -d

# Wait for databases to initialize
sleep 30

# Check all services are healthy
docker compose ps

# View logs
docker compose logs -f api-gateway
```

### 5. Verify Installation

```bash
# API health check
curl http://localhost:8000/health

# API docs
open http://localhost:8000/docs

# Frontend
open http://localhost:3000
```

---

## Development Mode (Without Docker)

### Start Databases Only

```bash
cd infra/docker
docker compose up -d postgres redis elasticsearch neo4j
```

### Run Services Locally

```bash
# Terminal 1: API Gateway
source .venv/bin/activate
cd apps/api-gateway
uvicorn src.main:app --reload --port 8000

# Terminal 2: Worker
source .venv/bin/activate
celery -A apps.worker.src.tasks worker --loglevel=info

# Terminal 3: Frontend
cd apps/web
npm run dev

# Terminal 4: Recon Engine (Rust)
cd apps/recon-engine
cargo run --release
```

---

## Adding AI Features

### Local LLM with Ollama

```bash
# Start Ollama
docker compose --profile ai up -d ollama qdrant

# Pull a model
docker exec -it reconx-ollama ollama pull llama3.1:8b

# Verify
curl http://localhost:11434/api/tags
```

### Using OpenAI API

Update `.env`:
```
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o
```

---

## Production Deployment (Kubernetes)

### Prerequisites
- Kubernetes cluster (EKS, GKE, AKS, or self-managed)
- kubectl configured
- Docker registry access

### Deploy

```bash
# Build and push images
docker compose build
docker compose push

# Apply K8s manifests
kubectl apply -k infra/k8s/overlays/production/

# Verify
kubectl get pods -n reconx
```

---

## Troubleshooting

### Common Issues

**Docker permission denied**:
```bash
sudo usermod -aG docker $USER
newgrp docker  # or logout/login
```

**PostgreSQL connection refused**:
```bash
docker compose logs postgres  # Check if healthy
docker compose restart postgres
```

**Elasticsearch memory error**:
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

**Recon tool not found**:
```bash
# Ensure Go bin is in PATH
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
```
