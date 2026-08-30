# SENTRY
### Lightweight SOC Alert Dashboard & Network Security Monitoring System

SENTRY is a lightweight **Network Security Monitoring (NSM)** and **SOC alert dashboard** built with **Python Flask, Scapy, SQLite, and React**.

It collects network packet metadata and authentication events, applies deterministic rule-based detection logic to identify common attack patterns, stores generated security alerts, and presents them through a real-time security operations dashboard.

The system is designed for **local security monitoring, testing, demonstrations, and learning purposes**.

---

## Overview

SENTRY combines network telemetry, authentication events, rule-based threat detection, persistent storage, REST APIs, and a React-based SOC interface into a single system.

```text
┌──────────────────────────────┐
│     Network Interface        │
│        Scapy Capture         │
└──────────────┬───────────────┘
               │
               │ Packet Metadata
               ▼
┌──────────────────────────────┐
│                              │
│     Detection Engine         │
│        detector.py           │
│                              │
│  • Port Scan                 │
│  • SYN Flood                 │
│  • Brute Force               │
│                              │
└──────────────┬───────────────┘
               │
               │ Security Alerts
               ▼
┌──────────────────────────────┐
│        SQLite Database       │
│                              │
│  • alerts                    │
│  • network_events            │
│  • login_events              │
└──────────────┬───────────────┘
               │
               │ REST API / JSON
               ▼
┌──────────────────────────────┐
│        Flask Backend         │
│            :5050             │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       React Dashboard        │
│            :3000             │
│                              │
│  • Alert Queue               │
│  • Network Feed              │
│  • Security Metrics          │
│  • Live / Demo Mode          │
└──────────────────────────────┘
```

---

## Key Features

- Network packet metadata monitoring using **Scapy**
- Rule-based security detection engine
- Port scan detection
- TCP SYN flood detection
- SSH/FTP/RDP brute-force detection
- Deterministic threat scoring from **0–100**
- Alert severity classification
- Persistent SQLite storage
- RESTful Flask API
- React + Vite security dashboard
- Ranked alert queue
- Live network event feed
- Live Mode and Demo Mode
- Synthetic attack generation for testing
- Bulk demo data seeding
- Automated detection tests using Pytest
- Packet payloads are not stored by the monitoring layer

---

# Detection Engine

SENTRY currently implements three rule-based detections.

| Detection | Rule | Score | Severity |
|---|---|---:|---|
| `PORT_SCAN` | ≥ 10 unique destination ports from the same source IP within 10 seconds | 70 | HIGH |
| `SYN_FLOOD` | ≥ 50 TCP SYN packets with `ACK=0` within 5 seconds | 90 | CRITICAL |
| `BRUTE_FORCE` | ≥ 5 failed login attempts from the same source IP for the same service within 3 minutes | 80 | HIGH |

The detection engine is intentionally deterministic. The same input event sequence produces the same detection result and threat score.

---

## 1. Port Scan Detection

A port scan attempts to discover services exposed by a host by sending connection requests to multiple ports.

SENTRY tracks:

```text
source IP
destination IP
destination port
timestamp
```

A port scan alert is generated when the same source IP accesses at least **10 unique destination ports within a 10-second window**.

### Example

```text
192.168.1.50 → 192.168.1.20:21
192.168.1.50 → 192.168.1.20:22
192.168.1.50 → 192.168.1.20:23
192.168.1.50 → 192.168.1.20:25
...
```

If the number of unique destination ports reaches the configured threshold, SENTRY generates:

```text
Alert Type: PORT_SCAN
Threat Score: 70
Severity: HIGH
```

---

## 2. SYN Flood Detection

TCP normally establishes a connection using a three-way handshake:

```text
Client                  Server
  │                       │
  │────── SYN ───────────>│
  │<──── SYN-ACK ─────────│
  │────── ACK ───────────>│
  │                       │
       Connection
       Established
```

A SYN flood generates a large number of SYN requests without completing the normal handshake.

SENTRY monitors TCP packets where:

```text
SYN = 1
ACK = 0
```

An alert is generated when at least **50 qualifying packets occur within 5 seconds**.

```text
Alert Type: SYN_FLOOD
Threat Score: 90
Severity: CRITICAL
```

---

## 3. Brute-Force Detection

SENTRY also analyzes authentication events.

Supported services include:

```text
SSH   → 22
FTP   → 21
RDP   → 3389
```

The detection engine groups failed authentication attempts by:

```text
source IP + service
```

If at least **5 failed attempts occur within 3 minutes**, SENTRY generates a brute-force alert.

```text
Alert Type: BRUTE_FORCE
Threat Score: 80
Severity: HIGH
```

---

# Threat Scoring

SENTRY uses a deterministic integer threat score between **0 and 100**.

Current scoring:

```text
PORT_SCAN       → 70
BRUTE_FORCE     → 80
SYN_FLOOD       → 90
```

The score is used to prioritize alerts in the SOC dashboard.

The ranked alert endpoint sorts alerts by:

```text
threat_score DESC
```

This allows higher-risk alerts to appear first in the analyst queue.

---

# Network Telemetry

SENTRY captures **packet metadata rather than packet payload contents**.

Example metadata:

```text
SRC: 192.168.1.50:49152
DST: 192.168.1.20:22
PROTO: TCP
TIMESTAMP: 2026-08-30T12:30:10
```

The monitoring layer focuses on network characteristics such as:

- Source IP
- Destination IP
- Source port
- Destination port
- Protocol
- TCP flags
- Timestamp

This reduces unnecessary collection of application payload data.

---

# Standard Network Ports

SENTRY uses standard service ports when representing network activity.

| Port | Protocol / Service |
|---:|---|
| 21 | FTP |
| 22 | SSH |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 3389 | RDP |

Client applications commonly use dynamically allocated **ephemeral source ports**, which are different from well-known server-side service ports.

---

# Application Architecture

The application is divided into separate layers.

### Capture Layer

`capture.py`

Responsible for collecting network packet metadata using Scapy.

```text
Network Interface
       ↓
     Scapy
       ↓
Packet Metadata
```

---

### Detection Layer

`detector.py`

Contains the rule-based security detection logic.

```text
Network Events
      +
Login Events
      ↓
Detection Rules
      ↓
Security Alerts
```

The detection engine is separated from the Flask application so that detection logic can be tested independently.

---

### Database Layer

`database.py`

Provides SQLite persistence for:

```text
alerts
network_events
login_events
```

The database allows security events and generated alerts to remain available after individual API requests finish.

---

### API Layer

`app.py`

Provides the Flask REST API used by the frontend.

```text
React
  ↓
HTTP / JSON
  ↓
Flask API
  ↓
Detection / Database
```

---

### Frontend Layer

The frontend is implemented using:

- React
- Vite
- Vanilla CSS
- Chart.js

The dashboard consumes the Flask API and displays security telemetry in a SOC-style interface.

---

# Project Structure

```text
sentry_final/
│
├── backend/
│   ├── app.py
│   ├── detector.py
│   ├── database.py
│   ├── capture.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AlertList.jsx
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Header.jsx
│   │   │   └── NetworkFeed.jsx
│   │   │
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── api.js
│   │   └── main.jsx
│   │
│   ├── package.json
│   ├── package-lock.json
│   ├── vite.config.js
│   └── index.html
│
├── tests/
│   └── test_detection.py
│
├── README.md
└── ...
```

---

# REST API

## Statistics

### `GET /api/stats`

Returns dashboard summary statistics.

Example:

```json
{
  "total_events": 1200,
  "total_alerts": 15,
  "threat_score": 90
}
```

---

## Alerts

### `GET /api/alerts`

Returns security alerts stored in the database.

---

### `GET /api/alerts/ranked`

Returns alerts ordered by threat score.

```text
Highest threat
      ↓
90 - SYN_FLOOD
80 - BRUTE_FORCE
70 - PORT_SCAN
      ↓
Lowest threat
```

---

## Live Network Feed

### `GET /api/network/live`

Returns recent network metadata collected by the monitoring system.

---

## Login Analysis

### `POST /api/login/analyze`

Analyzes a login attempt and evaluates its security risk.

---

## Login Event Ingestion

### `POST /api/login-events`

Accepts authentication events and passes them through the detection engine.

Example event:

```json
{
  "source_ip": "192.168.1.50",
  "service": "SSH",
  "status": "failed"
}
```

---

## Operating Mode

### `GET /api/mode`

Returns the current monitoring mode.

Possible modes:

```text
LIVE MODE
DEMO MODE
```

### `POST /api/mode/toggle`

Switches between Live Mode and Demo Mode.

---

## Demo Attack Generation

### `POST /api/demo/trigger`

Generates a synthetic security event for testing the detection and dashboard pipeline.

Supported attack types:

```text
PORT_SCAN
SYN_FLOOD
BRUTE_FORCE
```

---

## Demo Data Seeding

### `POST /api/demo/seed`

Generates a large volume of synthetic network and alert data for dashboard demonstrations and performance testing.

---

# Live Mode

Live Mode uses Scapy to monitor the active network interface.

```text
Network Interface
       ↓
     Scapy
       ↓
Packet Metadata
       ↓
Detection Engine
       ↓
SQLite
       ↓
Flask API
       ↓
React Dashboard
```

Because packet capture interacts with network interfaces, the operating system may require elevated privileges depending on the environment.

---

# Demo Mode

Demo Mode allows the complete detection pipeline to be tested without relying on live network traffic.

Synthetic events can be generated for:

```text
Port Scan
SYN Flood
Brute Force
```

This is useful for:

- Local development
- UI testing
- Detection testing
- Demonstrations
- Environments where packet capture privileges are unavailable

Demo events should be clearly treated as **synthetic telemetry**, not real network attacks.

---

# Installation

## Prerequisites

Install the following:

- Python 3.10+
- Node.js 18+
- npm
- Git

For Live Mode:

- Scapy
- Permission to capture network traffic on the selected interface

---

# Backend Setup

From the project root:

```bash
python3 -m venv venv
```

Activate the virtual environment.

### macOS / Linux

```bash
source venv/bin/activate
```

### Windows

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

Start the Flask server:

```bash
python -m backend.app
```

The backend runs on:

```text
http://127.0.0.1:5050
```

---

# Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

The React development server runs on:

```text
http://localhost:3000
```

---

# Running Tests

From the project root:

```bash
PYTHONPATH=. pytest tests/
```

The test suite validates the rule-based detection engine, including the configured thresholds for:

```text
PORT_SCAN
SYN_FLOOD
BRUTE_FORCE
```

---

# Example Event Flow

A typical port-scan event can move through the system as follows:

```text
1. Network packet observed
          ↓
2. Scapy extracts packet metadata
          ↓
3. Network event recorded
          ↓
4. Detection engine evaluates event
          ↓
5. 10 unique ports detected
          ↓
6. PORT_SCAN alert generated
          ↓
7. Threat score = 70
          ↓
8. Alert stored in SQLite
          ↓
9. Flask API exposes alert
          ↓
10. React dashboard displays alert
```

---

# Security Design Considerations

SENTRY intentionally separates telemetry collection, detection, persistence, API handling, and visualization.

### Metadata-focused monitoring

The capture layer focuses on metadata instead of storing packet payloads.

### Deterministic detection

Detection rules use explicit thresholds rather than randomized or probabilistic scores.

### Modular detection engine

Detection logic is separated from the web application, making individual rules easier to test and extend.

### Synthetic testing

Demo Mode provides controlled test events without requiring real attacks to be performed against external systems.

---

# Limitations

SENTRY is a **lightweight rule-based NSM project**, not a production enterprise SIEM or IDS/IPS.

Current limitations include:

- Detection is based on fixed thresholds.
- Only three primary attack patterns are currently implemented.
- SQLite is intended for local/lightweight usage rather than large-scale distributed telemetry.
- Packet capture depends on local interface visibility and operating-system permissions.
- The system does not perform deep packet inspection.
- It does not provide full endpoint detection and response capabilities.
- It does not replace enterprise SIEM, IDS, IPS, firewall, or EDR platforms.
- Threshold
