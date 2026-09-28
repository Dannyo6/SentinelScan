<div align="center">

# SENTINELSCAN — Autonomous Web Security Auditing & Compliance Telemetry Platform

### Intelligent Reconnaissance & Real-Time Audit Telemetry Engine

*Point it. Authorize it. It evaluates, correlates, and scores defenses autonomously.*

---

![Python](https://img.shields.io/badge/PYTHON-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/FLASK-BACKEND-000000?style=for-the-badge&logo=flask&logoColor=white)
![React](https://img.shields.io/badge/REACT-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Orchestration](https://img.shields.io/badge/ORCHESTRATION-GOOGLE_GEMINI-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)
![Pytest](https://img.shields.io/badge/PYTEST-314_PASSING-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/LICENSE-MIT-green?style=for-the-badge)

</div>

---

## 🧭 Executive Overview

**SentinelScan** is an autonomous web security auditing and compliance telemetry platform engineered to evaluate the defensive posture of web applications and network infrastructure. Rather than relying on static, hardcoded checklist scans that blindly execute identical checks regardless of context, SentinelScan utilizes a high-level LLM agent orchestrator powered by **Google Gemini** that dynamically evaluates diagnostic findings at each milestone, adapts its assessment plan, and dispatches single-purpose diagnostic workers to build an exhaustive, risk-weighted compliance scorecard.

The platform couples a high-performance **Python/Flask REST backend** with an enterprise-grade **React 19 interactive telemetry dashboard** featuring reactive component primitives (MagicBento, ScanTerminal, GooeyNav, SpecularButton), backed by a non-blocking **Firestore observability logstore**.

> ⚠️ **Scope & Ethics Notice:** SentinelScan is strictly a defensive compliance assessment and diagnostic auditing platform designed for authorized security verification. All workers execute non-destructive, non-exploitative queries (DNS zone evaluation, SSL/TLS handshake inspection, HTTP security header verification, and cookie flags). It does not execute weaponized payloads or exploits.

---

## 🏛️ System Architecture

SentinelScan follows a strict separation of concerns across its three primary architectural tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   REACT 19 INTERACTIVE TELEMETRY UI                    │
│    • ScanTerminal (ASCII figlet, word-reveal spring animation)         │
│    • MagicBento (spotlight glow, particle magnetism scorecards)        │
│    • GooeyNav (fluid navigation tabs) & SpecularButton (WebGL canvas)  │
│    • Real-time REST polling & CustomEvent browser bridge               │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ HTTP REST (/api/v1/scans, /telemetry)
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      FLASK BACKEND & CONTROLLER                        │
│    • REST API Routing (/api/v1/scans, /reports, /telemetry)            │
│    • Background thread scan worker lifecycle management               │
│    • SSRF validator, IP subnet guards, and domain blocklists           │
│    • Firestore event pipeline sink & correlation trace management      │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Context & Milestone State
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  GEMINI AGENT WORKFLOW ORCHESTRATOR                    │
│    • Sole intelligence hub (apps/backend/agent/orchestrator.py)         │
│    • Evaluates worker telemetry in an adaptive feedback loop           │
│    • Quantifies risk vectors using mathematical CVSS v3.1 scoring      │
│    • Generates publication-ready PDF and JSON audit deliverables       │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Dispatches Tool Execution
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│            11 SINGLE-PURPOSE DIAGNOSTIC WORKERS (Zero Logic)           │
│    DNS • Reverse DNS • WHOIS • Port Availability • SSL/TLS Audit       │
│    HTTP Headers • Cookie Analysis • Robots.txt • Sitemap • DDoS WAF    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Autonomous Agent Logic & Workflow

Traditional scanners execute linear scripts that generate overwhelming walls of unstructured text. SentinelScan inverts this paradigm:

1. **Autonomous Decision Loop:** The Gemini agent is the sole decision-maker. It receives the target host and chooses the initial reconnaissance tool.
2. **Evidence-Driven Worker Sequencing:** When a worker completes, its structured JSON output is parsed by the agent. If the DNS lookup exposes multiple subdomains or open services, the agent prioritizes SSL/TLS and security header inspections on relevant endpoints.
3. **Dumb Workers Principle:** Diagnostic workers located in `apps/backend/workers/` contain **zero business logic, zero orchestration logic, and zero persistence**. Each worker accepts targeted inputs, performs a deterministic network or protocol query, and returns normalized JSON.
4. **Deterministic Fallback Engine:** For environments without external LLM connectivity, an offline deterministic state machine (`apps/backend/agent/orchestrator.py`) provides reliable assessment execution.
5. **Standardized Severity Scoring:** Findings are evaluated mathematically using CVSS v3.1 base metric equations rather than subjective heuristics.

---

## 🧰 Diagnostic Workers Specification

| Domain | Worker Identifier | Implementation Module | Technical Inspection Scope |
|---|---|---|---|
| **Topology** | `dns_lookup` | `dns_worker.py` | A, AAAA, MX, NS, TXT, CNAME, SPF resolution via `dnspython`; DNSSEC verification. |
| **Topology** | `reverse_dns_lookup` | `reverse_dns_worker.py` | PTR pointer validation, IPv4/IPv6 address normalization, and host correlation. |
| **Reconnaissance** | `whois_lookup` | `whois_worker.py` | Registrar status, creation dates, expiration horizons, and nameserver ownership. |
| **Reconnaissance** | `port_scan` | `portscan_worker.py` | Non-intrusive TCP port state audit via `python-nmap` with socket-connect fallback. |
| **Web Surface** | `ssl_check` | `ssl_worker.py` | X.509 validity, expiration dates, protocol versions (TLS 1.2/1.3), cipher suites. |
| **Web Surface** | `http_headers` | `headers_worker.py` | Audits HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| **Web Surface** | `cookie_analysis` | `cookie_worker.py` | Evaluates `Secure`, `HttpOnly`, and `SameSite` flags across all session cookies. |
| **Exposure** | `robots_txt_parse` | `robots_worker.py` | Disallowed path extraction, crawl-delay directives, and administrative exposure checks. |
| **Exposure** | `sitemap_parse` | `sitemap_worker.py` | Sitemap index parsing, canonical URI harvesting, and endpoint validation. |
| **Resilience** | `ddos_resilience_check` | `ddos_worker.py` | Passive CDN edge detection (Cloudflare, CloudFront), WAF detection, rate-limiting headers. |
| **Assessment** | `calculate_cvss` | `orchestrator.py` | Quantitative CVSS v3.1 base score computation and severity rating. |
| **Deliverables** | `generate_report` | `report_worker.py` | Formats aggregate findings into PDF (`reportlab`) and JSON compliance reports. |

---

## 📊 Dual UI & Telemetry Pipeline

SentinelScan delivers real-time observability across two complementary interfaces:

- **React 19 Telemetry Dashboard (`apps/frontend/react-app`):**
  - **`ScanTerminal`:** Real-time event log terminal featuring an ASCII figlet banner, word-by-word spring typing animations, and categorized status badges.
  - **`MagicBento`:** Multi-card bento grid with global spotlight effects, cursor particle magnetism, and interactive compliance categories.
  - **`GooeyNav` & `SpecularButton`:** Fluid tab selection and WebGL specular highlight canvas buttons.
- **Structured Observability Logstore:**
  - Non-blocking browser telemetry ingest via `POST /api/v1/telemetry`.
  - Batch event validation, correlation ID (`trace_id`, `session_id`) tracking, and thread-isolated Firestore logging sink.

---

## 🚀 Setup & Runbook

### Prerequisites
- **Python 3.11+** (tested and verified on Python 3.11 – 3.14)
- **Node.js 20+** and `npm`
- **Nmap** (optional; socket-connect fallback automatically activates if Nmap is absent)
- **Google Gemini API Key** (optional for live AI agent loop; offline deterministic mode is enabled by default)

### 1. Repository Configuration
Clone the repository and initialize environment variables:
```bash
git clone https://github.com/Dannyo6/SentinelScan.git
cd SentinelScan

cp .env.example .env
# Configure GEMINI_API_KEY in .env if using live AI orchestration
```

### 2. Python Backend Setup
Initialize the virtual environment and install backend dependencies:
```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Run the backend Flask REST service:
```bash
flask --app apps.backend.app run --port 5000
```
The REST API will be available at `http://127.0.0.1:5000/api/v1`.

### 3. Frontend Client Compilation & Dev Server
Navigate to the React application workspace:
```bash
cd apps/frontend/react-app
npm install

# Start development server with Hot Module Replacement (HMR)
npm run dev

# Compile production bundle
npm run build
```

Production static assets compile cleanly into `apps/frontend/react-app/dist/`.

---

## 🧪 Comprehensive Verification & Test Suite

SentinelScan maintains comprehensive, regression-tested test coverage across both its backend services and frontend telemetry runtime:

### Python Backend Suite (Pytest)
```bash
# Run all 314+ backend unit, integration, and worker tests:
pytest tests/
```
Covers:
- All 11 diagnostic worker contracts and network fault fallback mechanisms
- Offline agent orchestrator loops and Gemini client mock routines
- REST route validation, rate limiting, and SSRF prevention guards
- Firestore logstore schema, query filters, and rollups

### Frontend Telemetry Suite (Node Test Runner)
```bash
# Run JavaScript telemetry unit tests:
npm test
```
Covers:
- Event burst throttling and payload batching constraints
- Correlation IDs and trace inheritance
- Token authorization attachment and fail-safe beacon flush on page unload
- Zero-throw runtime resilience guarantees

---

## 📄 License & Compliance

Distributed under the **MIT License**. SentinelScan is strictly designed for legitimate system administration, internal network assessment, and authorized security compliance verification.
