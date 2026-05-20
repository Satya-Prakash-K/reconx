# ReconX — Autonomous Bug Bounty Intelligence Platform

---

## What is ReconX?

ReconX is a **fully autonomous, AI-powered bug bounty and security reconnaissance platform**. It is not a simple scanner — it is an **agent swarm**: a coordinated system of specialized AI agents that work together to discover, analyze, test, triage, and report security vulnerabilities, just like an experienced human pentester would — but running 24/7, at scale, without manual intervention.

You point it at a target URL. It does everything else:
- Crawls the entire attack surface
- Discovers hidden endpoints, parameters, and APIs
- Generates attack hypotheses
- Runs 14+ active vulnerability tests
- Triages and scores every finding
- Generates a ready-to-submit bug bounty report

It also enforces **program-aware policy** — you can configure exactly which tests are allowed, what domains are in-scope, what rate limits to respect, and what custom HTTP headers to send (e.g., `X-Bug-Bounty: username` required by Bugcrowd programs).

---

## Architecture Overview

ReconX is a **microservices platform** — multiple independent services, each responsible for one concern, communicating over a shared network. Every service runs in its own Docker container.

```
┌─────────────────────────────────────────────────────────────┐
│                        BROWSER (Next.js UI)                 │
│  Dashboard · Command Center · Programs · Findings ·         │
│  Live Feed · Report Builder · Triage · Heatmap · Graph      │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTP / WebSocket
┌───────────────────────────▼─────────────────────────────────┐
│                     API Gateway (FastAPI)                    │
│  Routes all UI requests to the correct backend service       │
└───┬─────────────┬──────────────┬──────────────┬─────────────┘
    │             │              │              │
    ▼             ▼              ▼              ▼
Autonomous    AI Engine     Triage Engine   Vuln Engine
Engine        (LLM/RAG)     (CVSS/CWE)     (active tests)
(main swarm)
    │
    ▼
PostgreSQL ← stores Programs, Findings, Scopes, Scan Events
    +
Redis      ← session cache, pub/sub
    +
Qdrant     ← vector memory for AI agents
    +
Neo4j      ← attack graph (relationships between findings)
    +
Kafka      ← event streaming between services
```

---

## The 8 AI Agents — What Each One Does

The core of ReconX is the **Agent Swarm** — 8 specialized agents that run in sequence for every scan cycle.

### 1. Planner Agent
**What it does:** Receives the target URL and decides the scan strategy.

It looks at the target and decides:
- `broad_scan` — crawl everything, test all attack surfaces
- `focused_scan` — concentrate on high-risk endpoints
- `api_focused` — prioritize REST/GraphQL API endpoints
- `auth_focused` — prioritize authentication and authorization flows

It also reads the **program policy** (what tests are allowed, what's out-of-scope) and embeds that into the scan plan. All subsequent agents follow this plan.

**Output:** Strategy name + reasoning, written into the shared scan state.

---

### 2. Recon Agent
**What it does:** Performs deep 5-level recursive crawling of the target.

It does NOT just fetch one page. It:
1. Fetches `robots.txt` → discovers hidden paths the site tries to hide from crawlers
2. Fetches `sitemap.xml` → gets every URL the site knows about
3. Parses every HTML page → extracts all links, forms, and input fields
4. Parses every JavaScript file → extracts API endpoint patterns like `/api/users/:id`
5. Follows all discovered links up to **5 levels deep**
6. Detects technologies (WordPress, .NET, React, GraphQL) from response headers and body

**BFS algorithm:** Uses Breadth-First Search so it explores broadly at each level before going deeper — ensuring maximum surface coverage within the crawl budget.

**Output:** A list of all discovered URLs, parameters, forms, and technologies.

---

### 3. Analysis Agent
**What it does:** Analyzes the discovered attack surface and identifies the riskiest targets.

It scores each endpoint:
- Does it have query parameters? (+risk)
- Does it accept file uploads? (+risk)
- Is it behind authentication? (+risk for IDOR testing)
- Does it touch financial data (cashier, billing, payment)? (+critical risk)
- Is it an API endpoint vs. a static page? (APIs are higher priority)

**Output:** Prioritized list of endpoints, ranked by attack potential.

---

### 4. Hypothesis Agent
**What it does:** For every parameter on every endpoint, generates a specific attack hypothesis.

This is the "brain" — it decides *what* to test and *why*.

For each parameter, it generates hypotheses like:
- "Parameter `id` is numeric and used in a database lookup → likely vulnerable to SQLi"
- "Parameter `file` accepts paths → likely vulnerable to LFI/Path Traversal"
- "Parameter `url` accepts URLs → likely vulnerable to SSRF"
- "Endpoint accepts JWT in Authorization header → test for algorithm confusion"

It only generates hypotheses for test categories **allowed by the program policy** — so if the policy says no SQLi testing, it skips those hypotheses entirely.

**Output:** List of (endpoint, parameter, attack_type, reasoning) tuples.

---

### 5. Tester Agent
**What it does:** Executes the actual vulnerability probes against the target.

For each hypothesis, it runs the corresponding test. Here are all 14 test categories:

#### SQLi (SQL Injection)
Injects `'`, `' OR '1'='1`, `; DROP TABLE` into parameters. Checks response for SQL error strings like `you have an error in your sql syntax`, `unclosed quotation mark`, `ora-`, `pg_query`. If found → confirmed SQLi.

#### XSS (Cross-Site Scripting)
Injects `<script>alert('xss')</script>`, `"><img src=x onerror=alert(1)>` into parameters. Checks if the payload appears **unencoded** in the response body. If reflected verbatim → confirmed reflected XSS.

#### LFI (Local File Inclusion / Path Traversal)
Injects `../../../etc/passwd`, `....//....//etc/passwd`, `/etc/passwd%00` into file-like parameters. Checks response for `root:x:0:0:` (the start of /etc/passwd). If found → confirmed LFI.

#### SSRF (Server-Side Request Forgery)
Injects `http://169.254.169.254/latest/meta-data/` (AWS metadata), `http://localhost/admin`, `http://127.0.0.1` into URL parameters. Checks for AWS metadata keywords or internal service responses.

#### CSRF (Cross-Site Request Forgery)
Inspects forms for missing `csrf_token`, `_token`, `X-CSRF-Token` fields. State-changing forms (POST/PUT/DELETE) without CSRF tokens are flagged.

#### CORS Misconfiguration
Sends requests with `Origin: https://evil.com` and checks if the `Access-Control-Allow-Origin` header echoes it back. If it does, any website can make cross-origin requests as the victim user.

#### IDOR (Insecure Direct Object Reference)
Detects numeric IDs in parameters (`?id=123`, `/users/456`) and increments/decrements them. If different IDs return different user data without authorization → IDOR confirmed.

#### Open Redirect
Injects `https://evil.com`, `//evil.com`, `javascript:alert(1)` into redirect parameters (`next`, `redirect`, `return_url`). Checks response for `Location: https://evil.com` headers.

#### SSTI (Server-Side Template Injection)
Injects `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`. Checks if `49` appears in the response — meaning the server executed the template expression. If `49` is in the response → SSTI confirmed.

#### Sensitive File Exposure (Misconfig)
Requests well-known sensitive paths:
- `/.env` — environment variables (DB passwords, API keys)
- `/.git/config` — git configuration (may reveal source code)
- `/phpinfo.php` — PHP configuration details
- `/wp-config.php` — WordPress database credentials
- `/backup.zip`, `/admin`, `/api/swagger.json`

Checks for HTTP 200 responses with actual content.

#### GraphQL
Sends `{"query":"{__schema{types{name}}}"}` to `/graphql`, `/api/graphql`. If the response contains `queryType` → introspection is enabled, exposing the full API schema to attackers.

#### JWT Weakness
Extracts JWT tokens from cookies and Authorization headers. Tests:
- **Algorithm confusion:** Modifies `alg` to `none` → server accepts unsigned token
- **Weak secret:** Tests common secrets (`secret`, `password`, `123456`) via HMAC

#### Command Injection
Injects `;id`, `|id`, `\`id\``, `$(id)` into parameters. Checks response for `uid=`, `gid=`, `root`, `www-data` — output of the Unix `id` command.

#### XXE (XML External Entity)
Sends crafted XML with `<!DOCTYPE` and `SYSTEM "file:///etc/passwd"` to XML-accepting endpoints. Checks if file contents appear in the response.

---

### 6. Risk Agent (Triager)
**What it does:** Scores every confirmed finding using CVSS 3.1 and maps to CWE/OWASP.

For each finding it assigns:
- **CVSS score** (0.0–10.0) based on attack vector, complexity, privileges required, impact
- **Severity** (Critical/High/Medium/Low/Info)
- **CWE ID** (e.g., CWE-89 for SQLi, CWE-79 for XSS, CWE-22 for Path Traversal)
- **OWASP category** (e.g., A03:2021-Injection)
- **Remediation guidance** specific to the vulnerability type

---

### 7. Reporter Agent
**What it does:** Compiles all findings into a structured report.

Formats supported:
- **HackerOne** — markdown with Summary, Severity, Steps to Reproduce, Impact, Remediation
- **Bugcrowd** — same structure, Bugcrowd taxonomy
- **Intigriti** — Intigriti format
- **CVE Advisory** — CVE-style disclosure
- **Executive Summary** — non-technical, for management
- **Technical Writeup** — full technical analysis with payloads

---

### 8. Memory Agent
**What it does:** Stores everything in the persistent database.

- Saves findings to PostgreSQL `findings` table
- Updates program finding counts
- Logs the full scan event to `scan_events` table
- Stores embeddings in Qdrant for AI-powered similarity search across past findings

---

## Features In Detail

### Programs — Bug Bounty Program Management

The Programs feature lets you define a **bug bounty program** before scanning.

**What you configure:**
| Field | Purpose |
|-------|---------|
| Name | Identifier (e.g., "eToro Managed Bug Bounty") |
| Platform | HackerOne / Bugcrowd / Intigriti / YesWeHack / Custom |
| Scope | In-scope domains (auto-parsed from pasted program text) |
| Out-of-scope | Domains/paths to never test |
| Allowed Tests | Checkboxes for each of the 14 vuln categories |
| Policy Preset | Conservative / Standard / Aggressive |
| Rate Limit | Max requests per second (1–10) |
| HTTP Header | Custom header sent with every request (e.g., `X-Bug-Bounty: username`) |
| Notes | Policy reminders (what not to test, special rules) |

**Policy presets:**
- **Conservative** — only safe passive checks (CORS, misconfig, XSS, SQLi, LFI, CSRF, Open Redirect)
- **Standard** — all of the above + SSRF, IDOR, SSTI, GraphQL, JWT
- **Aggressive** — everything including Command Injection and XXE

**How it enforces policy:** When a scan starts with a program selected, the policy is embedded in the scan state. The Hypothesis Agent checks the allowed tests list before generating any attack hypothesis. If a test type isn't allowed, no hypothesis is generated for it → no probe is sent.

**Safety guardrails (always enforced, regardless of policy):**
- Never send more than 10 requests to the same endpoint
- Never test destructive payloads (DROP TABLE, DELETE FROM, rm -rf)
- Never test DoS payloads
- Never follow redirects to out-of-scope domains

---

### Live Feed — Real-Time Event Stream

The Live Feed shows a real-time stream of what the engine is doing right now.

Every event from the scan is pushed into the event feed:
- `[finding]` — a confirmed vulnerability (shown in red/orange by severity)
- `[endpoint]` — a new URL discovered by the crawler
- `[change]` — scan phase transition (Planner → Recon → Testing etc.)
- `[asset]` — subdomain or technology discovered
- `[tech]` — technology stack detected (Express.js, MongoDB, etc.)

Events are delivered over **WebSocket** for zero-latency updates. The UI reconnects automatically if the connection drops.

---

### Findings — Vulnerability Database

All confirmed findings are stored in PostgreSQL and displayed in the Findings page.

Each finding record contains:
- Title, severity, category
- Affected URL + vulnerable parameter
- The exact proof-of-concept payload used
- CVSS score, CWE ID, OWASP mapping
- Evidence (what the response looked like)
- Remediation steps
- Status (new / confirmed / false_positive / fixed)

You can filter by severity, search by keyword, and expand each finding for full details.

---

### Report Builder — Ready-to-Submit Reports

The Report Builder generates a formatted bug bounty report from your confirmed findings.

It fetches real findings from the database and formats them for the target platform. The generated report includes:

```markdown
## Summary
[Vulnerability name and one-line description]

## Severity
**CRITICAL** (CVSS: 9.8)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

## Description
[Full technical description of the vulnerability]

**Affected URL:** `https://target.com/api/users`
**Vulnerable Parameter:** `id`
**Evidence:** [What the response contained]

## Steps to Reproduce
1. Navigate to the URL
2. Inject payload into the parameter
3. Observe the response

## Supporting Material
- CWE-89 (SQL Injection)
- OWASP: A03:2021-Injection

## All Confirmed Findings (N total)
[List of every finding from this scan]

## Impact
[What an attacker could do]

## Remediation
[Specific fix instructions]
```

---

### Triage — AI-Assisted Review

The Triage page lets you review findings and mark them as:
- ✅ Confirmed — real vulnerability
- ❌ False Positive — not exploitable
- 🔄 Needs More Info — requires further testing

The AI engine adds context: similar findings from past scans, public CVE references, and OWASP guidance.

---

### Attack Graph

The Attack Graph visualizes relationships between findings using Neo4j. It shows:
- Which endpoints are connected (shared authentication, shared database)
- Exploitation paths (e.g., SSRF → access internal API → IDOR → read other users' data)
- Vulnerability chains (multiple medium-severity issues that combine into a critical)

---

### Heatmap

A severity heatmap showing which parts of the target's URL tree have the most vulnerabilities. Useful for identifying the riskiest subsystems at a glance.

---

## Technology Stack — Every Package Explained

### Frontend

| Package | Why Used |
|---------|---------|
| **Next.js 14** | React framework with App Router, server components, and built-in API routes. Chosen because it supports both static rendering and real-time client components in the same app. |
| **TypeScript** | Type safety across all UI code — catches bugs at compile time. |
| **Framer Motion** | Smooth animations and transitions. Used for the agent pipeline cards animating between IDLE/ACTIVE/COMPLETED states and the modal slide-in effects. |
| **Lucide React** | Icon library — all the Shield, Zap, AlertTriangle icons throughout the UI. Chosen because it's tree-shakeable (only imports the icons you use). |
| **Tailwind CSS** | Utility-first CSS framework used alongside custom CSS for the glassmorphism effects, gradients, and dark theme. |

### Autonomous Engine (Python)

| Package | Why Used |
|---------|---------|
| **FastAPI** | High-performance async web framework. Chosen over Flask because it natively supports `async/await`, which is essential for running concurrent HTTP probes without blocking. |
| **Uvicorn** | ASGI server — runs FastAPI in production. Supports HTTP/1.1 and WebSocket simultaneously. |
| **httpx** | Async HTTP client. Used for all vulnerability probes. Chosen over `requests` because it's async — hundreds of probes can run concurrently without waiting for each other. |
| **asyncpg** | Async PostgreSQL driver. Used for all database reads/writes in the scan engine. Chosen over `psycopg2` because it's native async and 3x faster. |
| **beautifulsoup4 + lxml** | HTML parser. Used by the Recon Agent to extract links, forms, and parameters from crawled pages. `lxml` is the C-based parser backend — significantly faster than Python's built-in html.parser. |
| **structlog** | Structured logging — outputs JSON-formatted logs with fields like `session_id`, `phase`, `target`. Makes logs searchable in Grafana/Loki. |
| **pydantic** | Data validation for all API request/response models. The `SessionRequest`, `ProgramCreate` models use it. If a field is missing or wrong type, FastAPI automatically returns a 422 error with the exact field that failed. |

### AI Engine (Python)

| Package | Why Used |
|---------|---------|
| **LangChain** | Framework for building LLM-powered agents. Used for the ReconPlanner that decides scan strategy and the report generator. |
| **Ollama** | Local LLM runner. Allows running open-source models (Llama 3, Mistral) locally without sending data to OpenAI. Important for testing confidential targets. |
| **Qdrant** | Vector database. Stores embeddings of past findings so the AI can do semantic search — "find past findings similar to this new one." Used for deduplication and context-building. |
| **sentence-transformers** | Converts text (finding titles, descriptions) into vector embeddings for Qdrant storage. |

### API Gateway (Python)

| Package | Why Used |
|---------|---------|
| **FastAPI** | Same as engine — async performance is critical since the gateway proxies all UI requests to multiple backend services simultaneously. |
| **httpx** | Used for proxying requests to the autonomous engine, triage engine, etc. |
| **PyJWT** | JWT authentication for API routes. Validates tokens on protected endpoints. |

### Infrastructure

| Service | Why Used |
|---------|---------|
| **PostgreSQL 16** | Primary persistent database. Stores programs, findings, scopes, scan events, triage records, reports. Chosen for ACID compliance — findings are never partially written. |
| **Redis** | Session cache and pub/sub. Stores active scan sessions in memory for fast access. Also used for WebSocket event broadcasting between containers. |
| **Qdrant** | Vector similarity search. Powers "find similar findings" and AI deduplication. |
| **Neo4j** | Graph database. Models attack paths as a graph — nodes are endpoints/findings, edges are exploitation relationships. |
| **Elasticsearch** | Full-text search across findings and scan logs. Powers the findings search bar. |
| **Kafka + Zookeeper** | Event streaming. When a finding is confirmed, it's published to a Kafka topic so multiple services (triage engine, memory agent, report generator) can process it independently. |
| **Ollama** | Runs open-source LLMs locally (Llama 3.1, Mistral). The AI engine uses it for strategy planning and report enrichment. |
| **Prometheus** | Metrics collection. Tracks scan duration, findings count, requests/sec, error rates. |
| **Grafana** | Dashboard for Prometheus metrics. Visual monitoring of the platform's health. |
| **Loki** | Log aggregation. All container logs flow into Loki and are queryable in Grafana. |
| **Temporal** | Workflow orchestration. Manages long-running multi-step scan workflows with automatic retry on failure. |
| **Ray** | Distributed computing. Used for parallelizing vulnerability probes across multiple workers. A Ray cluster (1 head + 2 workers) shares the scanning load. |
| **Selenium + Chrome** | Headless browser for JavaScript-heavy targets that require actual browser rendering to discover endpoints. |

### Database Schema

**programs** — stores bug bounty programs
```
id, name, platform, allowed_tests, rate_limit_rps, notes, created_at
```

**scopes** — per-program domain scope rules
```
id, program_id, scope_type, value, is_in_scope, is_wildcard
```

**findings** — every confirmed vulnerability
```
id, workspace_id, program_id, scan_id,
title, severity, category, affected_url, param,
payload, cvss_score, cwe_id, owasp_category,
evidence, remediation, status, source_tool,
created_at, updated_at
```

**scan_events** — live feed events
```
id, session_id, workspace_id, event_type,
title, detail, severity, timestamp
```

---

## Complete Scan Flow — Step by Step

```
USER: Set up program with scope + policy
         ↓
USER: Enter target URL + select program → click Start Scan
         ↓
API: POST /session/start → creates session_id, starts background task
         ↓
[AGENT 1: PLANNER]
  - Reads target URL + policy
  - Chooses strategy: broad_scan / focused_scan / api_focused
  - Writes plan into shared state
         ↓
[AGENT 2: RECON] 
  - Fetches robots.txt + sitemap.xml
  - BFS crawl: level 1 → 2 → 3 → 4 → 5
  - At each level: parse HTML (BeautifulSoup) → extract links + forms
  - Parse JS files → extract API endpoint patterns
  - Detect technologies from headers
  - Output: 50-500 discovered URLs with their parameters
         ↓
[AGENT 3: ANALYSIS]
  - Score each endpoint by risk profile
  - Prioritize: API endpoints > forms > static pages
  - Prioritize: financial endpoints > regular endpoints
         ↓
[AGENT 4: HYPOTHESIS]
  - For each endpoint × parameter combination:
    - Check if test category is allowed by policy
    - Generate specific attack hypothesis with reasoning
  - Output: list of (url, param, attack_type) to test
         ↓
[AGENT 5: TESTER]
  - For each hypothesis, run the appropriate probe:
    - Build payload URL
    - Send HTTP request with custom headers
    - Analyze response for vulnerability indicators
    - If confirmed → add to findings list
  - Rate limit respected (sleep between requests)
         ↓
[AGENT 6: RISK / TRIAGER]
  - For each finding:
    - Assign CVSS score
    - Map to CWE ID
    - Map to OWASP category
    - Write remediation guidance
         ↓
[AGENT 7: REPORTER]
  - Compile all findings into structured report
  - Format for target platform (HackerOne/Bugcrowd/etc.)
         ↓
[AGENT 8: MEMORY]
  - Save all findings to PostgreSQL
  - Update program finding counts
  - Log scan events to scan_events table
  - Store embeddings in Qdrant
         ↓
FRONTEND: WebSocket receives real-time updates throughout
  - Live Feed updates with each event
  - Agent pipeline cards show IDLE → ACTIVE → COMPLETED
  - Findings counter increments as bugs are found
         ↓
USER: Review findings → Generate Report → Submit to bug bounty platform
```

---

## Bug Bounty Workflow

### For every real bug bounty program:

**1. Read the program policy** completely before creating it in ReconX.
Note: which subdomains are in scope, what tests are allowed, any rate limits, required headers.

**2. Create the program** at `/programs`:
- Paste the scope → domains are auto-detected
- Choose policy preset → fine-tune individual test toggles
- Add any required HTTP header (e.g., `X-Bug-Bounty: username`)
- Set rate limit to match program rules

**3. Start with low-traffic/demo endpoints** first:
- `*-demo.*` or `*-src.*` subdomains are safer
- Look for subdomains with **0 known issues** on Bugcrowd — less competition

**4. Go to Command Center** → select program → enter target → Start Scan

**5. Watch Live Feed** for real-time findings

**6. Review Findings page** — filter by severity, review each one

**7. Report Builder** → choose platform format → Generate → copy the report

**8. Submit** to the bug bounty platform and wait for triage

---

## Safety Guarantees

ReconX has hardcoded safety limits that cannot be overridden by any policy:

- **No destructive SQL** — never sends INSERT, UPDATE, DELETE, DROP payloads
- **No DoS** — never floods a single endpoint with more than 10 requests
- **No data exfiltration** — if a LFI probe exposes real file contents, testing stops
- **Scope enforcement** — crawl never follows links to out-of-scope domains
- **Rate limiting** — always respects the configured RPS limit; adds jitter to avoid pattern detection

---

## Summary

| Capability | Detail |
|-----------|--------|
| Crawl depth | 5 levels BFS |
| Vulnerability tests | 14 categories (SQLi, XSS, LFI, SSRF, CSRF, CORS, IDOR, Open Redirect, SSTI, Misconfig, GraphQL, JWT, CMDi, XXE) |
| Report formats | HackerOne, Bugcrowd, Intigriti, CVE Advisory, Executive Summary, Technical Writeup |
| Platforms supported | HackerOne, Bugcrowd, Intigriti, YesWeHack, Custom |
| Real-time updates | WebSocket live feed |
| Persistence | PostgreSQL for all findings + programs |
| AI memory | Qdrant vector DB for cross-scan similarity |
| Attack visualization | Neo4j graph + heatmap |
| Program policy | Per-program allowed tests, rate limits, custom headers, scope enforcement |
