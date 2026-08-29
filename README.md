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
│   ├── app.py                # Flask REST API endpoints & route handlers (with ML integration)
│   ├── detector.py           # Pure rule-based threat detection engine
│   ├── database.py           # SQLite database manager (alerts, login_events, network_events)
│   ├── capture.py            # Lightweight Scapy packet metadata collector
│   ├── ml_detector.py        # Unsupervised IsolationForest anomaly detection layer
│   ├── train_ml.py           # Script to train IsolationForest on historical login events
│   └── requirements.txt      # Backend Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.jsx             # Top nav with LIVE MODE vs DEMO MODE toggle
│   │   │   ├── StatSummary.jsx        # SOC summary metric cards
│   │   │   ├── LiveNetworkFeed.jsx    # Packet stream (SRC_IP:PORT → DST_IP:PORT)
│   │   │   ├── LogAlertFeed.jsx       # Structured security log alerts
│   │   │   ├── RankedAlertQueue.jsx   # Top threats sorted by threat_score DESC (e.g., 90/100)
│   │   │   └── LoginAnalyzer.jsx      # Rule-based login security analysis form
│   │   ├── services/
│   │   │   └── api.js                 # API service client connecting React to Flask
│   │   ├── App.jsx                    # Main SOC Dashboard container
│   │   ├── App.css                    # Dark glassmorphism SOC theme styling
│   │   └── main.jsx                   # React entry point
│   ├── index.html                     # HTML shell
│   ├── package.json                   # React + Vite dependencies
│   └── vite.config.js                 # Vite server & proxy configuration
├── tests/
│   ├── test_detection.py              # Pytest detection engine test suite
│   └── test_ml_detector.py            # Pytest suite for ML anomaly detection
└── README.md                          # Comprehensive guide & 2-day interview plan
```

---

## 3. Core Security Detections

| Alert Type | Rule / ML Engine | Threat Score | Severity | Description |
| :--- | :--- | :---: | :---: | :--- |
| **`PORT_SCAN`** | $\ge 10$ unique destination ports from same source IP in 10s | **70 / 100** | `HIGH` | Multiple destination ports probed within short time window |
| **`SYN_FLOOD`** | High rate ($\ge 50$) of TCP packets with `SYN=1, ACK=0` in 5s | **90 / 100** | `CRITICAL` | High rate of TCP SYN connection requests targeting target IP:port |
| **`BRUTE_FORCE`** | $\ge 5$ failed logins from same source IP on same service in 3m | **80 / 100** | `HIGH` | Repeated failed SSH/FTP/RDP login attempts |
| **`ML_LOGIN_ANOMALY`** | Unsupervised `IsolationForest` detecting anomalous login patterns | **Dynamic (60-100)** | `HIGH` / `MEDIUM` | Unusual login pattern based on historical density (time gap, failures, user count) |

---

## 4. Machine Learning Anomaly Detection Layer

Sentry features a hybrid detection capability combining deterministic signature rules with an unsupervised anomaly detector:
- **Model**: `scikit-learn` Isolation Forest trained locally using historical login data.
- **Features Extracted**:
  - `time_since_last_attempt`: Seconds elapsed since the last login from this IP.
  - `recent_failures`: Number of authentication failures in the last 10 minutes from this IP.
  - `distinct_usernames`: Distinct usernames attempted in the last 10 minutes.
  - `hour`: Time of day (0-23) to establish baseline usage hours.
- **Model Persistence**: Serialized model is saved to `backend/sentry_model.pkl`.
- **Training**: Run `python -m backend.train_ml` to manually fit the model on your SQLite event database (requires at least 50 login events).

---

## 5. Networking Accuracy & Port Standard

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
| `POST` | `/api/login-events` | Ingest login attempt event (triggers rules & ML layers) |
| `GET` | `/api/mode` | Current mode (`LIVE MODE` vs `DEMO MODE`) |
| `POST` | `/api/mode/toggle` | Toggle mode between Live and Demo |
| `POST` | `/api/demo/trigger` | Trigger synthetic attack test (`PORT_SCAN`, `SYN_FLOOD`, `BRUTE_FORCE`) |

---

## 7. How to Run Locally

### Step 1: Start Backend (Flask API)
```bash
# From project root
./venv/bin/python -m backend.app
# Server runs on http://127.0.0.1:5050
```

### Step 2: Train ML Model
```bash
# Trains model on local data once database contains >= 50 login events
./venv/bin/python -m backend.train_ml
```

### Step 3: Start Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
# Dashboard opens on http://localhost:3000
```

### Step 4: Run Automated Tests
```bash
./venv/bin/pytest tests/
```

---

## 8. Live Mode vs Demo Mode

- **LIVE MODE**: Sniffs packet metadata (`scapy`) on local active machine network interfaces.
- **DEMO MODE**: UI toggle allowing 1-click generation of synthetic Port Scan, SYN Flood, and Brute Force attacks without requiring root privileges.

---

## 8. 2-Day Interview Learning Plan

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

## 9. ATS Resume Bullets

- **Engineered a real-time Network Security Monitoring (NSM) & SOC Alert Dashboard** to detect network anomalies, port scans, and SYN flood attacks across active machine interfaces **using Python Flask, Scapy packet metadata extraction, and React.js.**
- **Developed a rule-based threat detection engine with deterministic risk scoring (0–100)** to identify and triage Port Scans ($\ge 10$ unique ports/10s), SYN Floods, and SSH/FTP Brute-Force login attempts **by building sliding time-window thresholding algorithms in Python.**
- **Built modular RESTful APIs and an interactive SOC console featuring Ranked Alert Queues and IP Entity Profiling** to accelerate security analyst incident response times **by leveraging Flask-CORS, Chart.js, React (Vite), and Pytest automated testing (100% test pass rate).**
