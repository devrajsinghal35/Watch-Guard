# WATCH GUARD 🛡️
### Real-Time Network Security Monitoring & AI Incident Response SOC Console

**Watch Guard** is an enterprise-grade Network Security Monitoring (NSM) and SOC Operations Console built with **Python Flask**, **SQLite**, **React**, **Vite**, **Chart.js**, and **Google Gemini AI**. It ingests live network packet metadata and authentication telemetry, applies rule-based threat detection mapped to **MITRE ATT&CK**, performs regex-based **Data Loss Prevention (DLP)** scanning, and leverages an **AI Copilot** to generate incident response playbooks and `iptables` remediation rules.

---

## 🌟 Key Features & Architecture

- **🤖 AI Incident Response Copilot (Google Gemini API)**:
  - Generates real-time incident playbooks with executive summaries, root-cause analyses, confidence scoring, and specific Linux `iptables` firewall rules to drop malicious traffic.
- **🔍 Regex-Based Data Loss Prevention (DLP)**:
  - Scans packet payloads in real-time for unencrypted sensitive data (SSNs, PCI Credit Cards, API Bearer Tokens, Internal Secret Headers) and redacts PII automatically.
- **📊 Interactive SOC Analytics & Graphs (Chart.js)**:
  - **Threat Severity Matrix**: Real-time distribution across Low, Medium, High, and Critical risk levels.
  - **Live Telemetry Throughput**: Tracks real packet byte throughput (Bytes/sec) aggregated in 1-second time buckets.
  - **Top Flagged Threat Sources**: Ranks top attacker IP addresses by incident frequency.
- **⚡ DevSecOps & Automated CI/CD**:
  - Integrated GitHub Actions pipeline (`.github/workflows/devsecops.yml`) running automated **Pytest** suites and **Bandit SAST** security analysis on every push.
- **🎯 MITRE ATT&CK Aligned Detection Engine**:
  - Detects SYN Floods, Port Scans, Brute Force attacks, and Data Exfiltration across **50,000+ analyzed events**.

---

## 🛡️ Rule-Based Detections & MITRE ATT&CK Mapping

| Detection Vector | MITRE ATT&CK ID | Rule Condition | Threat Score | Severity |
|---|---|---|---:|---|
| **PORT_SCAN** | `T1046` | ≥ 5 unique destination ports probed from same source IP within 10s | 70 | HIGH |
| **SYN_FLOOD** | `T1498.001` | ≥ 8 TCP SYN packets (unacknowledged) targeting port within 5s | 90 | CRITICAL |
| **BRUTE_FORCE** | `T1110.001` | ≥ 3 failed login attempts (SSH/FTP/HTTP) from same source IP within 3m | 80 | HIGH |
| **DLP_VIOLATION** | `T1048` | Unencrypted SSN (`XXX-XX-XXXX`), Credit Card, or API Key found in payload | 95 | CRITICAL |

---

## 🔌 REST API Endpoints

Base URL: `http://127.0.0.1:5050`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/feed` | Consolidated dashboard telemetry feed (stats, alerts, network events, mode) |
| `GET` | `/api/stats` | Aggregate metrics & severity counts (50,000+ event telemetry count) |
| `GET` | `/api/alerts` | Security alerts log history |
| `POST` | `/api/ai/analyze-incident` | Query AI Copilot (Gemini API) to generate incident playbook & `iptables` rule |
| `POST` | `/api/demo/seed` | Seed 52,480 demo packets & balanced attack vector alerts |
| `POST` | `/api/reset` | Purge database and reset live packet capture |

---

## 📁 Project Structure

```text
Watch-Guard/
├── .github/
│   └── workflows/
│       └── devsecops.yml   # GitHub Actions CI/CD (Pytest + Bandit SAST)
├── backend/
│   ├── app.py              # Flask REST API & routes
│   ├── ai_copilot.py       # AI Incident Response Copilot (Gemini API)
│   ├── capture.py          # Network packet capture & telemetry module
│   ├── database.py         # SQLite persistence layer
│   ├── detector.py         # MITRE ATT&CK threat detection engine
│   ├── dlp_engine.py       # Regex Data Loss Prevention scanner
│   └── requirements.txt    # Python backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/     # ChartsSection, AlertList, NetworkFeed, Header
│   │   ├── App.jsx         # Watch Guard React SOC Console
│   │   └── api.js          # API service layer
│   └── package.json        # Frontend React dependencies
├── tests/
│   ├── test_detection.py   # Pytest NIDS detection unit tests
│   └── test_dlp.py         # Pytest DLP regex scanner unit tests
└── README.md
```

---

## 🚀 Quick Setup & Installation

### Prerequisites
- **Python**: 3.10+
- **Node.js**: 18+ & **npm**

### 1. Backend Setup

```bash
# Clone the repository
git clone https://github.com/devrajsinghal35/Watch-Guard.git
cd Watch-Guard

# Create & activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Export your Gemini API Key for AI Copilot (Optional)
export GEMINI_API_KEY="your_api_key_here"

# Start backend server
python3 -m backend.app
```
*Backend runs at: `http://127.0.0.1:5050`*

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
*Frontend SOC Console runs at: `http://localhost:3000`*

---

## 🧪 Testing & Security Auditing

```bash
# Run unit tests
PYTHONPATH=. pytest tests/

# Run SAST Security Audit
bandit -r backend/
```

---

## ⚖️ License & Disclaimer

Built for defensive security monitoring, educational demonstrations, and local development. Only monitor networks and systems you own or have explicit authorization to assess.
