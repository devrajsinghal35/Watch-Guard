# WATCH GUARD
Lightweight SOC Alert Dashboard & Network Security Monitoring System

WATCH GUARD is a lightweight Network Security Monitoring (NSM) and SOC alert dashboard built with Python Flask, Scapy, SQLite, and React. It collects network packet metadata and authentication events, applies deterministic rule-based detection, stores alerts, and exposes them via a real-time dashboard.

Intended for local security monitoring, testing, demonstrations, and learning.

---

## Architecture

```text
Network Interface (Scapy) → Detection Engine (detector.py)
                           → SQLite (alerts, network_events, login_events)
                           → Flask API (:5050)
                           → React Dashboard (:3000)
```

Layers:
- Capture: `capture.py` (Scapy packet metadata)
- Detection: `detector.py` (rule-based engine)
- Database: `database.py` (SQLite)
- API: `app.py` (Flask REST)
- Frontend: React + Vite + Chart.js

---

## Detections & Scoring

Deterministic rules (same input → same output).

| Detection     | Rule                                                                 | Score | Severity |
|--------------|----------------------------------------------------------------------|------:|----------|
| PORT_SCAN    | ≥ 10 unique dest ports from same source IP within 10s               | 70    | HIGH     |
| SYN_FLOOD    | ≥ 50 TCP SYN (ACK=0) within 5s                                      | 90    | CRITICAL |
| BRUTE_FORCE  | ≥ 5 failed logins (SSH/FTP/RDP) from same source IP within 3 minutes| 80    | HIGH     |

Threat score: 0–100. Alerts ranked by `threat_score DESC`.

---

## Telemetry

Captures packet metadata only (no payloads):

- src/dst IP, src/dst port, protocol, TCP flags, timestamp

Common ports used:

- 21 FTP, 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS, 3389 RDP

---

## REST API

Base: `http://127.0.0.1:5050`

- `GET /api/stats` – dashboard summary
- `GET /api/alerts` – all alerts
- `GET /api/alerts/ranked` – alerts sorted by threat score
- `GET /api/network/live` – recent network events
- `POST /api/login/analyze` – analyze a login attempt
- `POST /api/login-events` – ingest login event
- `GET /api/mode` – current mode (`LIVE` / `DEMO`)
- `POST /api/mode/toggle` – switch mode
- `POST /api/demo/trigger` – generate synthetic attack (PORT_SCAN, SYN_FLOOD, BRUTE_FORCE)
- `POST /api/demo/seed` – bulk demo data

---

## Modes

### Live Mode
- Uses Scapy on active interface.
- May require elevated privileges.

### Demo Mode
- Generates synthetic events for testing and demos.
- No real attacks required.

---

## Project Structure

```text
watch_guard/
├── backend/
│   ├── app.py
│   ├── detector.py
│   ├── database.py
│   ├── capture.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── App.jsx
│   │   ├── api.js
│   │   └── ...
│   ├── package.json
│   └── vite.config.js
├── tests/
│   └── test_detection.py
└── README.md
```

---

## Setup

Prerequisites: Python 3.10+, Node.js 18+, npm, Git.  
For Live Mode: Scapy + capture permissions.

### Backend

```bash
python3 -m venv venv
# macOS/Linux
source venv/bin/activate
# Windows
venv\Scripts\activate

pip install -r backend/requirements.txt
python -m backend.app
```

Backend runs at: `http://127.0.0.1:5050`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at: `http://localhost:3000`

### Tests

```bash
PYTHONPATH=. pytest tests/
```

---

## Limitations

- Fixed-threshold rules; no ML or probabilistic scoring.
- Only three attack types implemented.
- SQLite for local/lightweight use.
- Packet capture depends on OS/interface permissions.
- No deep packet inspection, EDR, or full SIEM capabilities.
- Possible false positives in high-traffic environments.

---

## Future Improvements (ideas)

- More detection rules (DNS anomalies, ICMP floods, suspicious outbound connections).
- Configurable thresholds.
- Alert lifecycle (ack, dedup).
- WebSocket streaming.
- PostgreSQL, RBAC, API auth.
- Containerization, SIEM integration, MITRE ATT&CK mapping.

---

## Tech Stack

- Frontend: React, Vite, CSS, Chart.js
- Backend: Python, Flask
- Network: Scapy
- DB: SQLite
- API: REST/JSON
- Tests: Pytest
- CORS: Flask-CORS

---

## Disclaimer

For educational, defensive monitoring, authorized testing, and local dev only. Only monitor networks/systems you own or have explicit permission to assess.

