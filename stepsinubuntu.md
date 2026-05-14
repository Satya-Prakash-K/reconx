# Step-by-Step Guide: Setting up ReconX in a Fresh Ubuntu VMware Instance

Since you have just installed a fresh instance of Ubuntu in VMware and pushed your code to GitHub, follow these exact step-by-step instructions inside your Ubuntu VM to get **ReconX** up and running.

---

## Phase 1: VMware & System Preparation

Open the **Terminal** app inside your Ubuntu VM (`Ctrl` + `Alt` + `T`) and execute the following steps:

### 1. Enable VMware Tools (For easy Copy-Paste & Screen Resizing)
```bash
sudo apt-get update
sudo apt-get install -y open-vm-tools open-vm-tools-desktop
```
*(Tip: If copy-pasting from Windows to Ubuntu doesn't work immediately, log out of Ubuntu and log back in, or restart the VM once.)*

### 2. Install Essential System Dependencies
```bash
sudo apt-get install -y git curl wget build-essential pkg-config cmake libssl-dev libcurl4-openssl-dev libsasl2-dev libzstd-dev apt-transport-https ca-certificates software-properties-common
```

---

## Phase 2: Clone Your Repository from GitHub

Since your codebase is safely stored in your GitHub account, clone it directly into your Ubuntu VM:

### 1. Clone the Repo
```bash
# Clone your repository
git clone https://github.com/Satya-Prakash-K/reconx.git

# Navigate into the project directory
cd reconx
```

---

## Phase 3: Install Docker & Python 3.11+

ReconX services run inside Docker containers, and local scripts require Python.

### 1. Install Docker & Docker Compose
```bash
# Download and install Docker automatically
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh

# Allow running docker without 'sudo'
sudo usermod -aG docker $USER
```
**⚠️ CRITICAL STEP:** You **MUST** apply the new group permissions. Run the following command or fully restart your Ubuntu VM before proceeding:
```bash
newgrp docker
```
Verify Docker works without sudo:
```bash
docker ps
```

### 2. Install Python 3.11 & Virtual Environment Tools
Ubuntu 22.04 usually comes with Python 3.10. Let's ensure Python 3.11+ is fully available:
```bash
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
```

---

## Phase 4: Execute ReconX Setup Automation Scripts

Make sure you are inside the `reconx` directory (`cd ~/reconx`). We will now execute the pre-built setup automation scripts sequentially.

### 1. Make Scripts Executable
```bash
chmod +x scripts/*.sh
```

### 2. Run Base Setup
Initializes local data directories, certificates, and base Python environments.
```bash
./scripts/setup.sh
```

### 3. Run Vulnerability Engine Setup
Installs Go, local bug bounty scanner binaries (Nuclei, subfinder, httpx), and prepares Ray clustering.
```bash
./scripts/setup-vuln-engine.sh
```
*(Note: If prompted for your password to install system packages, enter your Ubuntu user password.)*

### 4. Run Triage Engine Setup
Downloads local embedding models (`all-MiniLM-L6-v2`) for AI deduplication and PDF generation tools.
```bash
./scripts/setup-triage-engine.sh
```

### 5. Run Autonomous Engine Setup
Installs Playwright browser automation engines and registers the `reconx` command-line tool globally.
```bash
./scripts/setup-autonomous-engine.sh
```

---

## Phase 5: Start the Platform Stack

With all dependencies installed, let's spin up the distributed microservices, databases, and message queues.

### 1. Navigate to Docker Infrastructure Directory
```bash
cd infra/docker
```

### 2. Pull Base Container Images (Optional but speeds up launch)
```bash
docker compose --profile all pull
```

### 3. Launch Services (Optimized for your VM: 8GB RAM / 6 Cores / 52GB Storage)

Since you have allocated **8GB RAM** and **6 CPU Cores** to your VMware instance, launching the entire heavyweight stack simultaneously (including high-memory local LLMs and ClickHouse analytics engines) might trigger Linux out-of-memory (OOM) kills. 

To ensure maximum performance and absolute stability within your **8GB RAM** limit while leveraging all **6 cores**, use the tailored **Core Security Services Profile**:

```bash
# Starts core databases, API gateways, async workers, vulnerability engines, and AI triage
docker compose --profile core --profile vuln --profile triage --profile ai up -d
```

*(Note: Your **52GB storage** allocation is perfectly sufficient for the Docker base images, PostgreSQL schemas, and persistent Qdrant/Neo4j graph layers.)*

Check startup progress:
```bash
docker compose ps
```

---

## Phase 6: Accessing ReconX

### Option A: From Inside the Ubuntu VM's Browser (Firefox)
Open Firefox inside your Ubuntu VM and go to:
- **Web Dashboard:** [http://localhost:3000](http://localhost:3000)
- **API Gateway Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Neo4j Graph Browser:** [http://localhost:7474](http://localhost:7474)
- **Qdrant Vector DB Dashboard:** [http://localhost:6333/dashboard](http://localhost:6333/dashboard)

### Option B: From your Windows Host OS Browser
If you prefer using your main Windows browser (Chrome/Edge) to control ReconX running inside the VM:

1. Find your Ubuntu VM's internal IP address by running this command in the Ubuntu terminal:
   ```bash
   ip a | grep "inet "
   ```
   Look for an IP address like `192.168.x.x` (usually under `ens33` or `eth0`).

2. Open your Windows web browser and enter the VM's IP address with the port:
   - **Dashboard:** `http://192.168.x.x:3000`
   - **API Docs:** `http://192.168.x.x:8000/docs`

---

## Phase 7: Run Your First Autonomous Scan via CLI

Open a terminal inside your Ubuntu VM and test the global CLI tool:

```bash
# Verify CLI status
reconx status

# Start an autonomous security operation against an authorized target
reconx scan --target https://your-authorized-target.com --mode autonomous --cycles 3
```
