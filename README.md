# 🔍 ReconX — AI-Powered Autonomous Bug Bounty Reconnaissance Platform

> Enterprise-grade reconnaissance automation for authorized security testing and responsible disclosure programs.

⚠️ **LEGAL DISCLAIMER**: This platform is designed **exclusively** for authorized security testing within bug bounty programs. Unauthorized use against systems without explicit permission is **illegal and unethical**.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Next.js 15 Frontend                         │
│              (shadcn/ui · Recharts · Framer Motion)                │
├──────────────────────────────────────────────────────────────────────┤
│                    FastAPI + gRPC API Gateway                       │
│            (JWT Auth · RBAC · Rate Limiting · WebSocket)           │
├───────────────────┬──────────────────┬───────────────────────────────┤
│   Temporal        │   Kafka          │   Redis Streams              │
│   Workflows       │   Message Queue  │   Event Processing           │
├───────────────────┴──────────────────┴───────────────────────────────┤
│                     Celery Task Workers                             │
├──────────────────────────────────────────────────────────────────────┤
│  Rust Recon Engine  │  AI Engine (LangGraph · CrewAI · DSPy)       │
│  (Plugin System)    │  (Qdrant · RAG · Ollama/vLLM/OpenAI)        │
├──────────────────────────────────────────────────────────────────────┤
│  PostgreSQL  │  Elasticsearch  │  Neo4j  │  Redis  │  Qdrant      │
└──────────────────────────────────────────────────────────────────────┘
```

## ✨ Features

### Recon Capabilities
- **Subdomain Enumeration**: subfinder, amass, assetfinder, findomain, crt.sh, ASN, reverse DNS
- **DNS Analysis**: dnsx, massdns, DNS takeover detection
- **HTTP Probing**: httpx, TLS fingerprinting, WAF detection, tech fingerprinting
- **Port Scanning**: naabu, rustscan, masscan, nmap
- **URL Collection**: gau, waybackurls, katana, hakrawler
- **JS Intelligence**: SecretFinder, LinkFinder, source-map extraction, token leakage
- **Visual Recon**: Aquatone, EyeWitness, favicon hashing
- **Cloud Exposure**: S3, Azure Blobs, GCP Buckets, Firebase
- **API Discovery**: GraphQL, Swagger/OpenAPI, Postman collections

### AI Features
- 🤖 Autonomous recon planning agent
- 🎯 AI attack surface classification
- ⚡ High-value asset prioritization
- 📊 Risk scoring engine
- 📝 AI-generated recon summaries
- 🔗 Endpoint clustering
- 🔍 Semantic search over findings
- 🗺️ AI-generated attack path suggestions

### Platform Integrations
- HackerOne, Bugcrowd, Intigriti, YesWeHack
- Custom scope list import

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose v2+
- 16GB+ RAM recommended

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/reconx.git
cd reconx
cp .env.example .env
# Edit .env with your configuration
```

### 2. Start with Docker Compose

```bash
# Start core services
docker compose -f infra/docker/docker-compose.yml --profile core up -d

# Start with monitoring
docker compose -f infra/docker/docker-compose.yml --profile monitoring up -d

# Start everything
docker compose -f infra/docker/docker-compose.yml --profile all up -d
```

### 3. Access

| Service | URL |
|---------|-----|
| Frontend Dashboard | http://localhost:3000 |
| API Gateway | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Grafana | http://localhost:3001 |
| Neo4j Browser | http://localhost:7474 |
| Temporal UI | http://localhost:8088 |

---

## 🛠️ Development Setup

See [docs/setup.md](docs/setup.md) for detailed development environment setup.

### VM Deployment (Ubuntu 22.04 LTS — Recommended)

```bash
# See scripts/setup.sh for automated setup
chmod +x scripts/setup.sh
./scripts/setup.sh
```

---

## 📁 Monorepo Structure

```
reconx/
├── apps/
│   ├── api-gateway/      # FastAPI + gRPC gateway
│   ├── recon-engine/      # Rust recon core + plugin system
│   ├── ai-engine/         # AI/ML services
│   ├── worker/            # Celery + Temporal workers
│   └── web/               # Next.js 15 frontend
├── libs/
│   ├── shared-python/     # Shared Python utilities
│   └── proto/             # gRPC protobuf definitions
├── plugins/
│   ├── recon-tools/       # Recon tool plugins
│   └── integrations/      # Platform integrations
├── infra/
│   ├── docker/            # Docker Compose files
│   ├── k8s/               # Kubernetes manifests
│   └── terraform/         # Infrastructure as Code
├── db/
│   ├── migrations/        # Database migrations
│   └── schemas/           # Schema definitions
├── docs/                  # Documentation
└── scripts/               # Setup & utility scripts
```

---

## 🔒 Security

- Strict scope enforcement with out-of-scope blocking
- Rate limiting (global, per-target, per-tool)
- Safe-mode throttling
- AES-256-GCM secrets encryption
- JWT + RBAC authentication
- Full audit logging
- All scanning is scope-validated before execution

---

## 📄 License

MIT License with responsible disclosure clause. See [LICENSE](LICENSE).
