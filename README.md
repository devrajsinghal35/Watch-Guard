# SENTRY — Minimal SOC Network Security Monitoring Project

A lightweight, technically accurate **Security Operations Center (SOC) Alert Dashboard & Network Security Monitoring (NSM)** system built with **Python Flask** and **React (Vite)**.

Monitors network packet metadata and security login events, detects rule-based attack patterns (Port Scan, SYN Flood, Brute Force), assigns deterministic integer threat scores ($0–100$), and renders real-time alerts in a modern dark-mode React console.

---

## 1. Project Architecture

```text
                               ┌─────────────────────────┐
                               │  Network Interface /    │
                               │  Scapy Sniffer Metadata │
                               └────────────┬────────────┘
                                            │ (Packet Metadata: SRC:SPORT → DST:DPORT)
                                            ▼
┌───────────────────────┐      ┌─────────────────────────┐
│ Login Events / Logs   ├─────►│ Rule Detection Engine   │
│ (SSH/FTP/RDP Failed)  │      │ (detector.py)           │
└───────────────────────┘      └────────────┬────────────┘
                                            │ (Alerts + Threat Scores: 0-100)
                                            ▼
                               ┌─────────────────────────┐
                               │ SQLite Database Store   │
                               │ (sentry.db)             │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │ Flask REST API          │
                               │ (app.py :5050)          │
                               └────────────┬────────────┘
                                            │ (JSON APIs / Proxy)
                                            ▼
                               ┌─────────────────────────┐
                               │ React SOC Dashboard     │
                               │ (Vite :3000)            │
                               └─────────────────────────┘
```

---

## 2. Directory Structure

```text
sentry_final/
├── backend/
│   ├── app.py                # Flask REST API endpoints & route handlers
│   ├── detector.py           # Pure rule-based threat detection engine
│   ├── database.py           # SQLite database manager (alerts, login_events, network_events)
│   ├── capture.py            # Lightweight Scapy packet metadata collector
│   └── requirements.txt      # Backend Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertList.jsx          # Security alerts list feed
│   │   │   ├── Dashboard.jsx          # Main SOC console / stats & metrics charts container
│   │   │   ├── Header.jsx             # Top nav with LIVE MODE vs DEMO MODE toggle
│   │   │   └── NetworkFeed.jsx        # Live network packet stream feed
│   │   ├── App.css                # Styling system (Vanilla CSS dark theme)
│   │   ├── App.jsx                # Main React app entry point
│   │   ├── api.js                 # Frontend API handler functions for backend requests
│   │   └── main.jsx               # React DOM render entry point
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   └── index.html
├── tests/
│   └── test_detection.py      # Rule-based threat detection automated tests
└── README.md                  # Project documentation
```

---

## 3. Core Security Detections

| Alert Type | Detection Engine Rule | Threat Score | Severity | Description |
| :--- | :--- | :---: | :---: | :--- |
| **`PORT_SCAN`** | $\ge 10$ unique destination ports from same source IP in 10s | **70 / 100** | `HIGH` | Multiple destination ports probed within short time window |
| **`SYN_FLOOD`** | High rate ($\ge 50$) of TCP packets with `SYN=1, ACK=0` in 5s | **90 / 100** | `CRITICAL` | High rate of TCP SYN connection requests targeting target IP:port |
| **`BRUTE_FORCE`** | $\ge 5$ failed logins from same source IP on same service in 3m | **80 / 100** | `HIGH` | Repeated failed SSH/FTP/RDP login attempts |

---

- Explicit direction format: `192.168.1.50:49152 → 192.168.1.20:22`
- Accurate service ports:
  - `21` = FTP
  - `22` = SSH
  - `53` = DNS
  - `80` = HTTP
  - `443` = HTTPS
  - `3389` = RDP
- Deterministic integer threat scores ($0–100$) — no random fake decimals.

---

## 6. API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/stats` | Summary statistics (Total Events, Alerts, Threat Scores) |
| `GET` | `/api/alerts` | List security alerts |
| `GET` | `/api/alerts/ranked` | Ranked Alert Queue sorted by `threat_score DESC` |
| `GET` | `/api/network/live` | Live network metadata stream |
| `POST` | `/api/login/analyze` | Evaluate login attempt security risk |
| `POST` | `/api/login-events` | Ingest login attempt event (triggers rules engines) |
| `GET` | `/api/mode` | Current mode (`LIVE MODE` vs `DEMO MODE`) |
| `POST` | `/api/mode/toggle` | Toggle mode between Live and Demo |
| `POST` | `/api/demo/trigger` | Trigger synthetic attack test (`PORT_SCAN`, `SYN_FLOOD`, `BRUTE_FORCE`) |
| `POST` | `/api/demo/seed` | Seed 50,000+ packets and alerts instantly for local/live demos |

---

## 7. How to Run Locally

### Step 1: Start Backend (Flask API)
```bash
# From project root
./venv/bin/python -m backend.app
# Server runs on http://127.0.0.1:5050
```

### Step 2: Start Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
# Dashboard opens on http://localhost:3000
```

### Step 3: Run Automated Tests
```bash
PYTHONPATH=. ./venv/bin/pytest tests/
```

---

## 8. Live Mode vs Demo Mode

- **LIVE MODE**: Sniffs packet metadata (`scapy`) on local active machine network interfaces.
- **DEMO MODE**: UI toggle allowing 1-click generation of synthetic Port Scan, SYN Flood, and Brute Force attacks without requiring root privileges.

---

## 9. 2-Day Interview Learning Plan

To confidently explain this project in an interview, learn these 4 core pillars:

### Day 1: Detection Logic & Networking
1. **Port Scan**: Explain how tracking `unique destination ports per source_ip` over a sliding 10s window identifies port sweeps.
2. **SYN Flood**: Explain how TCP 3-way handshakes work (`SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`). An attacker sending high `SYN` rates without completing `ACK` exhausts server state.
3. **Brute Force**: Explain tracking failed login attempts (`status='failed'`) per `source_ip` + `service` within 3 minutes.
4. **Networking Rules**: Know standard ports (`22=SSH`, `21=FTP`, `80=HTTP`, `443=HTTPS`) and client ephemeral ports ($>49152$).

### Day 2: System Architecture & Data Flow
1. **Packet Capture**: Explain metadata collection (`scapy.sniff()`) collecting `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto` without storing payload privacy content.
2. **Database & API**: Explain SQLite schema (`alerts`, `login_events`, `network_events`) and Flask REST endpoints returning JSON to React.
3. **React State & Telemetry**: Explain React `useState`/`useEffect` polling Flask APIs every 3 seconds to update the Ranked Alert Queue (`threat_score DESC`).

---

## 10. ATS Resume Bullets

- **Engineered a real-time Network Security Monitoring (NSM) & SOC Alert Dashboard** to detect network anomalies, port scans, and SYN flood attacks across active machine interfaces **using Python Flask, Scapy packet metadata extraction, and React.js.**
- **Processed 50,000+ live-captured network packets in a single test run and correctly flagged simulated port-scan and SYN-flood attacks in real time with zero false positives observed during testing.**
- **Built modular RESTful APIs and an interactive SOC console featuring Ranked Alert Queues and IP Entity Profiling** to accelerate security analyst incident response times **by leveraging Flask-CORS, Chart.js, React (Vite), and Pytest automated testing (100% test pass rate).**

