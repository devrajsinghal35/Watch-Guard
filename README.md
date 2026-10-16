# Watch Guard

### Real-Time Network Security Monitoring & Incident Response SOC Console

Watch Guard is a Network Security Monitoring (NSM) and Security Operations Center (SOC) Console built with Python Flask, SQLite, React, Vite, and Chart.js. It ingests network packet metadata and authentication telemetry, applies rule-based threat detection mapped to MITRE ATT&CK techniques, performs regex-based Data Loss Prevention (DLP) payload scanning, and provides an incident response engine that generates remediation playbooks and Linux `iptables` mitigation rules.

---

## Architecture & Features

- **Incident Response Assistant**:
  - Analyzes active network security alerts to generate remediation playbooks, root-cause analyses, confidence ratings, and Linux `iptables` mitigation rules. Supports Gemini and OpenAI APIs with a deterministic fallback engine.
- **Regex-Based Data Loss Prevention (DLP)**:
  - Inspects packet payloads for unencrypted sensitive information (SSNs, credit card numbers, API bearer tokens, and internal confidential headers) with automated redaction.
- **SOC Operations Dashboard (Chart.js)**:
  - **Threat Severity Matrix**: Distribution across Low, Medium, High, and Critical risk tiers.
  - **Telemetry Throughput**: Real-time packet throughput (Bytes/sec) aggregated across rolling time windows.
  - **Top Flagged Threat Sources**: Aggregated ranking of source IPs by triggered incidents.
- **DevSecOps Pipeline**:
  - GitHub Actions workflow (`.github/workflows/devsecops.yml`) running automated Pytest test suites and Bandit SAST security scans.
- **MITRE ATT&CK Aligned Detection Engine**:
  - Detects SYN Floods, Port Scans, Credential Brute Force attacks, and Data Exfiltration in sliding temporal windows.

---

## Detection Rules & MITRE ATT&CK Mapping

| Detection Vector | MITRE ATT&CK ID | Rule Condition | Threat Score | Severity |
|---|---|---|---:|---|
| **PORT_SCAN** | `T1046` | ≥ 5 unique destination ports probed from same source IP within 10s | 70 | HIGH |
| **SYN_FLOOD** | `T1498.001` | ≥ 8 TCP SYN packets (unacknowledged) targeting port within 5s | 90 | CRITICAL |
| **BRUTE_FORCE** | `T1110.001` | ≥ 3 failed login attempts (SSH/FTP/HTTP) from same source IP within 3m | 80 | HIGH |
| **DLP_VIOLATION** | `T1048` | Unencrypted SSN, Credit Card, or API Key found in payload | 95 | CRITICAL |

---

## REST API Specification

Default Host: `http://127.0.0.1:5050`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service health check and operational mode status |
| `GET` | `/api/dashboard/feed` | Consolidated telemetry payload (statistics, alerts, live packets) |
| `GET` | `/api/stats` | Aggregated threat score metrics and severity counts |
| `GET` | `/api/alerts` | Security alert history with query filters (`limit`, `type`, `severity`) |
| `GET` | `/api/alerts/ranked` | High-priority security alerts ordered by threat score |
| `GET` | `/api/network/live` | Recent network packet telemetry stream |
| `POST` | `/api/login-events` | Ingest external authentication telemetry |
| `POST` | `/api/login/analyze` | Single authentication event risk assessment |
| `POST` | `/api/ai/analyze-incident` | Generate incident response playbook and firewall rules |
| `POST` | `/api/mode/toggle` | Toggle between live capture and simulation mode |
| `POST` | `/api/demo/trigger` | Trigger synthetic attack vectors (Port Scan, SYN Flood, Brute Force) |
| `POST` | `/api/demo/seed` | Populate database with synthetic packet traffic and alert fixtures |
| `POST` | `/api/reset` | Clear database tables and restart packet capture |

---

## Project Structure

```text
Watch-Guard/
├── .github/
│   └── workflows/
│       └── devsecops.yml       # GitHub Actions CI/CD (Pytest + Bandit SAST)
├── backend/
│   ├── app.py                  # Flask application routes and telemetry controller
│   ├── ai_copilot.py           # Incident response playbook engine (Gemini/OpenAI/Deterministic)
│   ├── capture.py              # Packet telemetry capture and synthetic flow generator
│   ├── database.py             # SQLite persistence layer and WAL-mode database interface
│   ├── detector.py             # MITRE ATT&CK rule-based sliding-window detection engine
│   ├── dlp_engine.py           # Regex-based deep packet inspection and DLP scanner
│   └── requirements.txt        # Python backend dependencies
├── frontend/
│   ├── index.html              # Main HTML entrypoint
│   ├── package.json            # Node.js dependencies and build scripts
│   ├── vite.config.js          # Vite build configuration and API reverse proxy
│   ├── vercel.json             # Vercel deployment routing configuration
│   └── src/
│       ├── main.jsx            # React root application mount
│       ├── App.jsx             # Main dashboard layout and state coordination
│       ├── App.css             # Design system styling and layout definitions
│       ├── api.js              # Frontend REST API client
│       └── components/
│           ├── Header.jsx           # Top navigation bar, status indicator, and mode toggles
│           ├── Dashboard.jsx        # Summary KPI metric counters
│           ├── ChartsSection.jsx    # Chart.js severity, throughput, and source analytics
│           ├── AlertList.jsx        # Incident triage list with playbook integration
│           ├── NetworkFeed.jsx      # Streaming live packet telemetry feed
│           └── LoginTriageModal.jsx # Interactive authentication risk triage tool
├── tests/
│   ├── test_detection.py       # Unit tests for port scan, SYN flood, and brute force detection
│   └── test_dlp.py             # Unit tests for regex data loss prevention scanner
├── render.yaml                 # Render cloud deployment specification
└── README.md                   # Project documentation
```

---

## Setup & Running Locally

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Backend Setup

```bash
# Clone repository
git clone https://github.com/devrajsinghal35/Watch-Guard.git
cd Watch-Guard

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# (Optional) Set LLM API Key for Incident Playbook generation
export GEMINI_API_KEY="your-gemini-key"
# or
export OPENAI_API_KEY="your-openai-key"

# Run Flask backend server
python3 -m backend.app
```
Backend server will be accessible at: `http://127.0.0.1:5050`

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Frontend console will be accessible at: `http://localhost:3000`

---

## Testing & Security Audits

```bash
# Run unit test suite
pytest tests/

# Run static application security testing (SAST)
bandit -r backend/ -ll
```
