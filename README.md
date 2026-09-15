# WATCH GUARD 🛡️
### Real-Time Network Security Monitoring & SOC Operations Console

**Watch Guard** is a modern Network Security Monitoring (NSM) and SOC alert dashboard built with **Python Flask**, **SQLite**, **React**, **Vite**, and **Chart.js**. It collects live network packet metadata and authentication triage events, applies rule-based threat detection, ranks security incidents, and visualizes real-time metrics through an interactive glassmorphic dashboard.

---

## 🌟 Key Features & Visualizations

- **Interactive Threat Graphs (Chart.js)**:
  - **Threat Severity Matrix**: Doughnut chart visualizing distribution across Low, Medium, High, and Critical risk levels.
  - **Live Telemetry Throughput**: Line chart tracking packet sizes and event throughput over time.
  - **Top Flagged Threat Sources**: Horizontal bar chart ranking top attacker IP addresses by incident count.
- **Incident & Feed Triage**:
  - Instant search filtering by IP address, alert type, or description.
  - Filter pills for quick severity triage (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Live Packet Stream with pause/resume controls and protocol tabs (`ALL`, `TCP`, `UDP`).
- **Interactive Authentication Triage Tool**:
  - Built-in triage modal tool to test custom authentication logs against rule-based threat engine.
- **Demo & Live Modes**:
  - **Live Mode**: Continuously streams packet telemetry into the security dashboard.
  - **Demo Mode**: Instant 50,000+ sample packet generator for quick system testing and demonstration.

---

## 🏗️ Architecture

```text
Network Telemetry → Detection Engine (detector.py)
                  → SQLite Database (watch_guard.db)
                  → Flask REST API (:5050)
                  → React + Vite SOC Console (:3000)
```

### Core Components:
- `backend/app.py`: Flask REST API service.
- `backend/capture.py`: Network packet metadata capture & simulation engine.
- `backend/detector.py`: Deterministic threat detection engine.
- `backend/database.py`: SQLite persistence layer.
- `frontend/src/`: React 18 + Chart.js + Lucide icons dashboard UI.

---

## 🛡️ Rule-Based Detections

| Detection Vector | Rule Condition | Threat Score | Severity Level |
|---|---|---:|---|
| **PORT_SCAN** | ≥ 10 unique destination ports probed from same source IP within 10s | 70 | HIGH |
| **SYN_FLOOD** | ≥ 50 TCP SYN packets (ACK=0) targeting port within 5s | 90 | CRITICAL |
| **BRUTE_FORCE** | ≥ 5 failed login attempts (SSH/FTP/RDP) from same source IP within 3m | 80 | HIGH |

---

## 🔌 REST API Endpoints

Base URL: `http://127.0.0.1:5050`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/dashboard/feed` | Consolidated high-performance dashboard telemetry feed (stats, alerts, network events, mode) |
| `GET` | `/api/stats` | Summary dashboard metrics & severity counts |
| `GET` | `/api/alerts` | Security alerts log history |
| `GET` | `/api/alerts/ranked` | Alerts ordered by threat score (`DESC`) |
| `GET` | `/api/network/live` | Live stream packet metadata |
| `GET` | `/api/mode` | Current operating mode (`LIVE` / `DEMO`) |
| `POST` | `/api/mode/toggle` | Switch between Live & Demo modes |
| `POST` | `/api/demo/trigger` | Trigger synthetic attack vector (`PORT_SCAN`, `SYN_FLOOD`, `BRUTE_FORCE`) |
| `POST` | `/api/demo/seed` | Seed 50,000+ demo packets instantly |
| `POST` | `/api/login/analyze` | Submit authentication payload for risk triage |

---

## 📁 Project Structure

```text
watch_guard/
├── backend/
│   ├── app.py            # Flask API & routes
│   ├── capture.py        # Packet capture module
│   ├── database.py       # SQLite database interface
│   ├── detector.py       # Threat detection engine
│   └── requirements.txt  # Python backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/   # ChartsSection, AlertList, NetworkFeed, Header, Dashboard, LoginTriageModal
│   │   ├── App.jsx       # Main Watch Guard React application
│   │   ├── App.css       # Glassmorphism dark SOC theme
│   │   └── api.js        # API service layer
│   ├── index.html        # Watch Guard HTML entry point
│   ├── package.json      # React project dependencies
│   └── vite.config.js    # Vite dev server & proxy settings
├── tests/
│   └── test_detection.py # Pytest detection unit tests
└── README.md
```

---

## 🚀 Quick Setup & Installation

### Prerequisites
- **Python**: 3.10+
- **Node.js**: 18+ & **npm**

### 1. Backend Setup

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Run backend API server
python -m backend.app
```
Backend service runs at: `http://127.0.0.1:5050`

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```
Frontend SOC console runs at: `http://localhost:3000`

### 3. Running Unit Tests

```bash
PYTHONPATH=. pytest tests/
```

---

## ⚖️ Disclaimer

Watch Guard is built for defensive security monitoring, educational demonstrations, and local development. Only monitor networks and systems you own or have explicit authorization to assess.
