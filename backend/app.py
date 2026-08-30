import os
import random
import time
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.database import Database
from backend.detector import DetectionEngine
from backend.capture import PacketCapturer

# Define backend and database paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "backend", "sentry.db")

app = Flask(__name__)
CORS(app) # Enable CORS to allow requests from the React frontend

db = Database(DB_PATH)
detector = DetectionEngine()
capturer = PacketCapturer()

# Live sniffing mode status parameters
IS_DEMO_MODE = False
SNIFFER_THREAD = None
SNIFFER_RUNNING = False

# Background sniffer loop worker thread function
def sniffer_worker():
    global SNIFFER_RUNNING
    while SNIFFER_RUNNING:
        pkt = capturer.sniff_packet()
        if pkt:
            db.insert_network_event(pkt)
            alerts = detector.process_packet(pkt)
            for a in alerts:
                db.insert_alert(a)
        time.sleep(0.5)

# API status endpoint to check server health
@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "NIDS API",
        "mode": "DEMO" if IS_DEMO_MODE else "LIVE"
    })

# API summary metrics values calculate endpoint
@app.route("/api/stats")
def stats_endpoint():
    return jsonify({"success": True, "data": db.get_stats()})

# Standard alerts logs history endpoint
@app.route("/api/alerts")
def alerts_endpoint():
    limit = request.args.get("limit", default=100, type=int)
    atype = request.args.get("type", default=None, type=str)
    sev = request.args.get("severity", default=None, type=str)
    alerts_list = db.get_alerts(limit=limit, alert_type=atype, severity=sev)
    return jsonify({"success": True, "count": len(alerts_list), "data": alerts_list})

# Ranked alerts table view endpoints
@app.route("/api/alerts/ranked")
def ranked_alerts_endpoint():
    limit = request.args.get("limit", default=100, type=int)
    ranked = db.get_ranked_alerts(limit=limit)
    return jsonify({"success": True, "count": len(ranked), "data": ranked})

# Live network events table data endpoint
@app.route("/api/network/live")
def live_network_endpoint():
    limit = request.args.get("limit", default=50, type=int)
    net_data = db.get_live_network(limit=limit)
    return jsonify({"success": True, "count": len(net_data), "data": net_data})

# Raw custom authentication log ingestion API
@app.route("/api/login-events", methods=["POST"])
def new_login_event():
    payload = request.get_json(silent=True) or {}
    required_keys = {"source_ip", "username", "status"}
    if not required_keys.issubset(payload.keys()):
        return jsonify({"success": False, "error": "Missing key details"}), 400

    evt = {
        "ts": time.time(),
        "source_ip": payload["source_ip"],
        "username": payload["username"],
        "service": payload.get("service", "SSH"),
        "port": int(payload.get("port", 22)),
        "status": payload["status"]
    }
    db.insert_login_event(evt)

    new_alerts = detector.process_login_event(evt)

    for a in new_alerts:
        db.insert_alert(a)

    return jsonify({"success": True, "alerts_generated": len(new_alerts), "alerts": new_alerts}), 201

# Single custom login verification form rules checker
@app.route("/api/login/analyze", methods=["POST"])
def analyze_login_attempt():
    payload = request.get_json(silent=True) or {}
    sip = payload.get("source_ip", "45.33.32.156")
    uname = payload.get("username", "root")
    srv = payload.get("service", "SSH")
    stat = payload.get("status", "failed")
    attempts = int(payload.get("failed_attempts", 40))
    port_num = int(payload.get("port", 22))

    if attempts >= 5 and stat.lower() == "failed":
        level = "HIGH"
        val = 80
        msg = f"{attempts} failed {srv} logins from {sip} on port {port_num}."
    else:
        level = "LOW"
        val = 15
        msg = f"Normal {srv} login attempt from {sip}."

    alert_obj = {
        "ts": time.time(),
        "alert_type": "BRUTE_FORCE" if level == "HIGH" else "LOGIN_ANALYSIS",
        "severity": level,
        "threat_score": val,
        "source_ip": sip,
        "source_port": 0,
        "destination_ip": "192.168.1.1",
        "destination_port": port_num,
        "protocol": "TCP",
        "description": f"Login Triage: User '{uname}' | Source: {sip} | {msg}",
    }
    db.insert_alert(alert_obj)

    return jsonify({
        "success": True,
        "result": {
            "risk_level": level,
            "threat_score": val,
            "reason": msg,
            "alert": alert_obj
        }
    })

# System active state mode fetch endpoint
@app.route("/api/mode")
def system_mode():
    global IS_DEMO_MODE
    return jsonify({"success": True, "demo_mode": IS_DEMO_MODE, "label": "DEMO MODE" if IS_DEMO_MODE else "LIVE MODE"})

# Toggle between demo simulation data and real interface packets
@app.route("/api/mode/toggle", methods=["POST"])
def toggle_system_mode():
    global IS_DEMO_MODE, SNIFFER_RUNNING, SNIFFER_THREAD
    IS_DEMO_MODE = not IS_DEMO_MODE
    
    if not IS_DEMO_MODE:
        if not SNIFFER_RUNNING:
            SNIFFER_RUNNING = True
            SNIFFER_THREAD = threading.Thread(target=sniffer_worker, daemon=True)
            SNIFFER_THREAD.start()
    else:
        SNIFFER_RUNNING = False

    return jsonify({"success": True, "demo_mode": IS_DEMO_MODE, "label": "DEMO MODE" if IS_DEMO_MODE else "LIVE MODE"})

# Simulates custom synthetic network events in demo mode
@app.route("/api/demo/trigger", methods=["POST"])
def trigger_demo_event():
    payload = request.get_json(silent=True) or {}
    atype = payload.get("attack_type", "PORT_SCAN").upper()
    
    triggered = []
    ts = time.time()

    if atype == "PORT_SCAN":
        src = f"192.168.1.{random.randint(50, 99)}"
        dst = "192.168.1.10"
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 3389, 8080, 8443]
        for p in ports:
            pkt = {"ts": ts, "source_ip": src, "source_port": random.randint(49152, 65535), "destination_ip": dst, "destination_port": p, "protocol": "TCP", "flags": "S", "length": 60}
            db.insert_network_event(pkt)
            res = detector.process_packet(pkt)
            triggered.extend(res)

    elif atype == "SYN_FLOOD":
        src = f"192.168.1.{random.randint(100, 150)}"
        dst = "192.168.1.20"
        port = 443
        for _ in range(55):
            pkt = {"ts": ts, "source_ip": src, "source_port": random.randint(49152, 65535), "destination_ip": dst, "destination_port": port, "protocol": "TCP", "flags": "S", "length": 54}
            db.insert_network_event(pkt)
            res = detector.process_packet(pkt)
            triggered.extend(res)

    elif atype == "BRUTE_FORCE":
        src = f"192.168.1.{random.randint(151, 200)}"
        srv_name = random.choice(["SSH", "FTP"])
        port = 22 if srv_name == "SSH" else 21
        for _ in range(6):
            evt = {"ts": ts, "source_ip": src, "username": "root", "service": srv_name, "port": port, "status": "failed"}
            db.insert_login_event(evt)
            res = detector.process_login_event(evt)
            triggered.extend(res)

    for a in triggered:
        db.insert_alert(a)

    return jsonify({
        "success": True,
        "attack_type": atype,
        "alerts_generated": len(triggered),
        "alerts": triggered
    })

# High-speed data seeding endpoint for generating 50,000+ packets instantly
@app.route("/api/demo/seed", methods=["POST"])
def seed_demo_data():
    ts = time.time()
    batch_size = 50250
    pkts = []
    
    # Pre-generate 50,250 packets in memory
    for i in range(batch_size):
        # Slightly randomized IPs/ports to make it look realistic
        src = f"192.168.1.{random.randint(10, 250)}"
        dst = f"192.168.1.{random.randint(2, 5)}"
        sport = random.choice([80, 443, 22, 53, 3389] + list(range(49152, 65535, 17)))
        dport = random.choice([80, 443, 22, 53, 3389])
        proto = random.choice(["TCP", "UDP"])
        length = random.randint(40, 1500)
        
        pkts.append({
            "ts": ts - (batch_size - i) * 0.05, # Spaced out timestamps
            "source_ip": src,
            "source_port": sport,
            "destination_ip": dst,
            "destination_port": dport,
            "protocol": proto,
            "length": length
        })

    # Batch insert network events
    db.insert_network_events_batch(pkts)

    # Insert a few high-quality demonstration alerts
    demo_alerts = [
        {
            "ts": ts - 30,
            "alert_type": "SYN_FLOOD",
            "severity": "CRITICAL",
            "threat_score": 90,
            "source_ip": "192.168.1.188",
            "source_port": 54321,
            "destination_ip": "192.168.1.3",
            "destination_port": 443,
            "protocol": "TCP",
            "description": "SYN Flood: High rate of TCP SYN packets (120 pkts/5s) from 192.168.1.188 targeting 192.168.1.3:443.",
            "status": "NEW"
        },
        {
            "ts": ts - 90,
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "threat_score": 70,
            "source_ip": "192.168.1.105",
            "source_port": 39485,
            "destination_ip": "192.168.1.4",
            "destination_port": 80,
            "protocol": "TCP",
            "description": "Port Scan: 18 ports probed from 192.168.1.105 within 10s.",
            "status": "NEW"
        },
        {
            "ts": ts - 300,
            "alert_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "threat_score": 80,
            "source_ip": "192.168.1.201",
            "source_port": 0,
            "destination_ip": "192.168.1.1",
            "destination_port": 22,
            "protocol": "TCP",
            "description": "SSH Brute Force: 12 failed logins from 192.168.1.201 targeting 'root' on port 22.",
            "status": "NEW"
        }
    ]

    for a in demo_alerts:
        db.insert_alert(a)

    return jsonify({
        "success": True,
        "packets_seeded": batch_size,
        "alerts_seeded": len(demo_alerts)
    })

if __name__ == "__main__":
    app.run(debug=True, port=8081)
