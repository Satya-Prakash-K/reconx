# ReconX v2: Complete Installation and Usage Guide (Ubuntu)

Welcome to **ReconX**, the next-generation autonomous AI security operations platform designed for authorized bug bounty and responsible disclosure programs.

This guide provides a comprehensive, step-by-step walkthrough on how to install, configure, start, and use ReconX on a fresh Ubuntu machine.

---

## 1. System Requirements

For a full deployment (running all AI models, databases, and scanning engines locally), you will need a robust system.

*   **OS:** Ubuntu 22.04 LTS (Recommended) or Debian 12.
*   **CPU:** Minimum 8 cores (16+ recommended for parallel processing).
*   **RAM:** Minimum 32GB (64GB+ recommended if running local LLMs and vector databases).
*   **Disk:** Minimum 200GB SSD (NVMe preferred for database IOPS).
*   **Network:** Stable broadband connection.

---

## 2. Installing Prerequisites

Before running the ReconX setup scripts, install the necessary underlying tools on your Ubuntu system.

Open your terminal and run the following commands:

### Update System
```bash
sudo apt-get update && sudo apt-get upgrade -y
```

### Install Basic Tools & Python
ReconX relies heavily on Python 3.11+.
```bash
sudo apt-get install -y curl wget git build-essential software-properties-common apt-transport-https ca-certificates lsb-release
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
```

### Install Docker & Docker Compose
The platform is containerized for easy deployment.
```bash
# Add Docker's official GPG key and repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add your user to the docker group (so you don't need 'sudo' for docker commands)
sudo usermod -aG docker $USER
# NOTE: You MUST log out and log back in (or run 'newgrp docker') for this to take effect.
```

### Install Node.js (For the Web Dashboard)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

---

## 3. Installing ReconX

Once prerequisites are installed, clone the repository and run the setup scripts in order. The platform is modular, and the setup is split into phases.

```bash
git clone https://github.com/your-org/reconx.git
cd ReconX
```

### Step 3.1: Base Platform Setup
This script initializes the directory structure, sets up the Python virtual environment (`.venv`), generates self-signed TLS certificates for local testing, and installs shared dependencies.
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```
*What happens:* It creates a `.env` file, sets up local data directories for Postgres/Redis/Neo4j, and installs core Python libraries.

### Step 3.2: Vulnerability Engine Setup
This installs external security tools required by the workers.
```bash
chmod +x scripts/setup-vuln-engine.sh
./scripts/setup-vuln-engine.sh
```
*What happens:* It installs Go, ProjectDiscovery tools (Nuclei, subfinder, httpx, naabu), Amass, sqlmap, and dependencies for interacting with Burp Suite and Ray clusters.

### Step 3.3: AI Triage Engine Setup
This sets up the AI models for deduplication and report generation.
```bash
chmod +x scripts/setup-triage-engine.sh
./scripts/setup-triage-engine.sh
```
*What happens:* It installs `sentence-transformers`, pre-downloads the embedding model (`all-MiniLM-L6-v2`), and installs `WeasyPrint` (for PDF report generation).

### Step 3.4: Autonomous Engine Setup
This installs tools for AI browser automation, CLI, and data analytics.
```bash
chmod +x scripts/setup-autonomous-engine.sh
./scripts/setup-autonomous-engine.sh
```
*What happens:* It installs Playwright (and Chromium browsers) for AI-driven DOM interaction, installs the `reconx` CLI tool globally, and sets up ClickHouse clients.

---

## 4. Starting the Platform

ReconX uses Docker Compose "Profiles" to let you run only the parts of the system you need.

Navigate to the docker directory:
```bash
cd infra/docker
```

### Option A: Run Everything (Recommended for powerful machines)
```bash
docker compose --profile all up -d
```

### Option B: Modular Startup
If you want to understand the stack or save resources, bring them up incrementally:
1.  **Core Databases & API:** `docker compose --profile core up -d`
    *(Starts Postgres, Redis, API Gateway)*
2.  **Vuln Engine:** `docker compose --profile vuln up -d`
    *(Starts Kafka, Temporal, Ray workers, Vuln API)*
3.  **AI & Knowledge Graph:** `docker compose --profile ai up -d`
    *(Starts Ollama, Qdrant, Neo4j, Elasticsearch)*
4.  **Triage & Reports:** `docker compose --profile triage up -d`
    *(Starts Triage API)*
5.  **Autonomous Swarm:** `docker compose --profile autonomous up -d`
    *(Starts Autonomous API)*
6.  **Analytics & UI:** `docker compose --profile analytics --profile monitoring up -d`
    *(Starts ClickHouse, Prometheus, Grafana)*

*To stop the platform, run: `docker compose --profile all down`*

---

## 5. Accessing the Platform

Once everything is running, you can access the various interfaces via your browser.

### Main Interfaces
*   **Web Dashboard:** [http://localhost:3000](http://localhost:3000) (The primary UI)
*   **API Gateway (Main Entry):** [http://localhost:8000/docs](http://localhost:8000/docs)
*   **ReconX CLI:** Type `reconx --help` in your terminal.

### Engine APIs (For direct programmatic access)
*   **Vuln Engine API:** [http://localhost:8002/docs](http://localhost:8002/docs)
*   **Triage Engine API:** [http://localhost:8003/docs](http://localhost:8003/docs)
*   **Autonomous Engine API:** [http://localhost:8004/docs](http://localhost:8004/docs)

### Databases & Observability
*   **Neo4j Knowledge Graph:** [http://localhost:7474](http://localhost:7474) (Default login: neo4j / reconx_secure_password)
*   **Qdrant Vectors:** [http://localhost:6333/dashboard](http://localhost:6333/dashboard)
*   **Ray Cluster Dashboard:** [http://localhost:8265](http://localhost:8265)
*   **Grafana Metrics:** [http://localhost:3001](http://localhost:3001) (Default login: admin / admin)

---

## 6. How to Use ReconX

### Workflow 1: The Autonomous AI Scan (Recommended)
This uses the full LangGraph agent swarm to discover, analyze, test, and report automatically.

**Via CLI:**
```bash
# Run an autonomous scan against a target for 3 cycles
reconx scan --target https://your-authorized-target.com --mode autonomous --cycles 3
```

**Via Web UI:**
1.  Navigate to **Command Center** in the Web Dashboard.
2.  Enter your target URL.
3.  Watch the **Agent Swarm Pipeline** as the Planner, Recon, Analysis, Hypothesis, Tester, Triager, and Reporter agents work sequentially.
4.  Watch the **Live Feed** to see real-time endpoints, tech stack discoveries, and findings pop up.

**What happens under the hood during an Autonomous Scan:**
1.  **Planner Agent:** Determines the strategy (e.g., broad recon first, deep fuzzing later).
2.  **Recon Agent:** Subdomains, port scanning, endpoint crawling.
3.  **Analysis Agent:** Classifies endpoints (Auth, GraphQL, API) and builds an attack surface map. Detects CI/CD leaks and secrets.
4.  **Hypothesis Agent:** The AI generates vulnerability hypotheses (e.g., "Parameter X might be vulnerable to SSRF because it fetches an image").
5.  **Testing Agent:** Executes specific payloads (Nuclei, sqlmap, browser automation) to validate the hypotheses.
6.  **Triage Agent:** Removes duplicates, calculates CVSS 3.1 scores, maps to CWE/OWASP, and calculates a risk score.
7.  **Memory Agent:** Stores the successful attack chain in the Neo4j Graph and Qdrant so the AI remembers it for future scans.

### Workflow 2: Triaging Existing Findings
If you have raw JSON findings from another tool, you can pass them through the AI Triage engine.

**Via CLI:**
```bash
reconx triage --workspace my-workspace --file my_raw_findings.json
```

**Via Web UI:**
1.  Navigate to **AI Triage**.
2.  Here you will see a prioritized list of findings. The engine automatically filters out false positives and clusters similar issues.
3.  You can view the estimated CVSS bars, Exploitability, and Impact scores.

### Workflow 3: Generating Bug Bounty Reports
Once a vulnerability is confirmed, you can generate a professional report automatically.

**Via CLI:**
```bash
# You must pass the finding JSON
reconx report --finding '{"title":"SQLi", "severity":"critical", "affected_url":"..."}' --format hackerone
```

**Via Web UI:**
1.  Navigate to **Report Builder**.
2.  Select a triaged finding.
3.  Choose the format: **HackerOne**, **Bugcrowd**, **Intigriti**, **CVE Advisory**, **Executive Summary**, or **Technical Writeup**.
4.  The AI will generate the report, including root cause, steps to reproduce, impact, and suggested fixes. Click "Copy" or "Export PDF".

### Workflow 4: Continuous Monitoring
You can instruct ReconX to constantly watch a target for changes.

**Via CLI:**
```bash
reconx monitor --target https://your-target.com --interval 3600
```
*What happens:* The system takes DOM snapshots and compares JavaScript files every hour. If a new API endpoint appears in a JS bundle, or a DNS record drifts, you will be alerted, and the AI will automatically generate a Nuclei template to test the new endpoint.

---

## 7. Troubleshooting

*   **Docker Container exits immediately:** Check the logs using `docker logs <container_name>`. Often this is due to insufficient RAM for Elasticsearch or Neo4j.
*   **Port Conflicts:** Ensure ports `8000-8004`, `3000`, `3001`, `4444`, `6333`, `7474`, `8123`, and `9200` are not in use by other local services.
*   **LLM Connection Refused:** Ensure the Ollama container is running (`docker ps | grep ollama`) and the model is pulled (`docker exec -it ollama ollama run llama3`).
*   **Permission Denied on setup scripts:** Make sure you ran `chmod +x scripts/*.sh` to make them executable.

---

## 8. Enterprise Deployment (Kubernetes)
If you are deploying to a production cluster instead of a local machine:

1.  **Install Istio Service Mesh:**
    ```bash
    istioctl install --set profile=demo -y
    kubectl label namespace reconx istio-injection=enabled
    ```
2.  **Deploy via Kustomize:**
    ```bash
    kubectl apply -k infra/k8s/
    ```
3.  **Or via Helm:**
    ```bash
    helm install reconx infra/helm/reconx/ -n reconx --create-namespace
    ```
4.  **Or via ArgoCD (GitOps):**
    ```bash
    kubectl apply -f infra/argocd/application.yml
    ```
