import os
import random
import time
import threading
import re
from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.database import Database
from backend.detector import DetectionEngine
from backend.capture import PacketCapturer
from backend.ai_copilot import ai_copilot

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "backend", "watch_guard.db")

app = Flask(__name__)
CORS(app)

db = Database(DB_PATH)
detector = DetectionEngine(db=db)
capturer = PacketCapturer()

IS_DEMO_MODE = False
SNIFFER_THREAD = None
SNIFFER_RUNNING = False

def sniffer_worker():
    global SNIFFER_RUNNING
    pkt_buffer = []
    last_flush = time.time()
    while SNIFFER_RUNNING:
        try:
            pkt = capturer.sniff_packet()
            if pkt:
                pkt_buffer.append(pkt)
                alerts = detector.process_packet(pkt)
                for a in alerts:
                    db.insert_alert(a)
                
                now = time.time()
                if len(pkt_buffer) >= 5 or (now - last_flush >= 0.5):
                    db.insert_network_events_batch(pkt_buffer)
                    pkt_buffer.clear()
                    last_flush = now
        except Exception as e:
            print("Sniffer worker error:", e)
        time.sleep(0.1)

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "NIDS API",
        "mode": "DEMO" if IS_DEMO_MODE else "LIVE"
    })

@app.route("/api/dashboard/feed")
def dashboard_feed_endpoint():
    return jsonify({
        "success": True,
        "data": {
            "stats": db.get_stats(),
            "alerts": db.get_alerts(limit=100),
            "networkEvents": db.get_live_network(limit=50),
            "demoMode": IS_DEMO_MODE,
        }
    })

@app.route("/api/stats")
def stats_endpoint():
    return jsonify({"success": True, "data": db.get_stats()})

@app.route("/api/alerts")
def alerts_endpoint():
    limit = request.args.get("limit", default=100, type=int)
    atype = request.args.get("type", default=None, type=str)
    sev = request.args.get("severity", default=None, type=str)
    alerts_list = db.get_alerts(limit=limit, alert_type=atype, severity=sev)
    return jsonify({"success": True, "count": len(alerts_list), "data": alerts_list})

@app.route("/api/alerts/ranked")
def ranked_alerts_endpoint():
    limit = request.args.get("limit", default=100, type=int)
    ranked = db.get_ranked_alerts(limit=limit)
    return jsonify({"success": True, "count": len(ranked), "data": ranked})

@app.route("/api/network/live")
def live_network_endpoint():
    limit = request.args.get("limit", default=50, type=int)
    net_data = db.get_live_network(limit=limit)
    return jsonify({"success": True, "count": len(net_data), "data": net_data})

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

@app.route("/api/ai/analyze-incident", methods=["POST"])
def ai_analyze_incident():
    payload = request.get_json(silent=True) or {}
    if not payload:
        return jsonify({"success": False, "error": "No alert data provided"}), 400
    
    analysis_result = ai_copilot.analyze_incident(payload)
    return jsonify({
        "success": True,
        "playbook": analysis_result
    })

@app.route("/api/mode")
def system_mode():
    global IS_DEMO_MODE
    return jsonify({"success": True, "demo_mode": IS_DEMO_MODE, "label": "DEMO MODE" if IS_DEMO_MODE else "LIVE MODE"})

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
        threading.Thread(target=seed_demo_data, daemon=True).start()

    return jsonify({"success": True, "demo_mode": IS_DEMO_MODE, "label": "DEMO MODE" if IS_DEMO_MODE else "LIVE MODE"})

@app.route("/api/reset", methods=["POST"])
def reset_system():
    global IS_DEMO_MODE, SNIFFER_RUNNING, SNIFFER_THREAD
    db.reset_all()
    detector.reset()
    
    IS_DEMO_MODE = False
    
    if not SNIFFER_RUNNING:
        SNIFFER_RUNNING = True
        SNIFFER_THREAD = threading.Thread(target=sniffer_worker, daemon=True)
        SNIFFER_THREAD.start()
        
    return jsonify({
        "success": True,
        "message": "System reset successfully. Switched to Live Mode and started fresh packet capture.",
        "demo_mode": False,
        "label": "LIVE MODE"
    })

# --- Adaptive Rulebook REST APIs ---

@app.route("/api/rules", methods=["GET"])
def list_rules():
    rules = db.get_all_rules()
    return jsonify({"success": True, "count": len(rules), "data": rules})

@app.route("/api/rules/candidates", methods=["GET"])
def list_candidates():
    status = request.args.get("status")
    cands = db.get_candidate_rules(status=status)
    return jsonify({"success": True, "count": len(cands), "data": cands})

@app.route("/api/rules/propose", methods=["POST"])
def propose_candidate_rule():
    payload = request.get_json(silent=True) or {}
    if not payload.get("pattern") or not payload.get("name"):
        return jsonify({"success": False, "error": "Rule name and pattern are required"}), 400

    # Safely validate regex pattern syntax
    try:
        re.compile(payload["pattern"])
    except re.error as e:
        return jsonify({"success": False, "error": f"Invalid regex pattern: {e}"}), 400

    candidate_id = f"CAND_{int(time.time()*1000)}"
    candidate = {
        "candidate_id": candidate_id,
        "name": payload["name"],
        "category": payload.get("category", "CUSTOM_ANOMALY"),
        "pattern": payload["pattern"],
        "target_field": payload.get("target_field", "payload"),
        "severity": payload.get("severity", "HIGH"),
        "threat_score": int(payload.get("threat_score", 75)),
        "rationale": payload.get("rationale", "Proactive signature proposed from telemetry anomaly."),
        "trigger_sample": payload.get("trigger_sample", ""),
        "validation_status": "VALIDATED",
        "false_positive_rate": 0.0
    }
    db.insert_candidate_rule(candidate)
    return jsonify({"success": True, "candidate_id": candidate_id, "candidate": candidate}), 201

@app.route("/api/rules/approve", methods=["POST"])
def approve_rule():
    payload = request.get_json(silent=True) or {}
    candidate_id = payload.get("candidate_id")
    approver = payload.get("approver", "SOC_LEAD")

    if not candidate_id:
        return jsonify({"success": False, "error": "candidate_id is required"}), 400

    ok, res = db.approve_candidate_rule(candidate_id, approver=approver)
    if not ok:
        return jsonify({"success": False, "error": res}), 400

    # Hot-reload rules in running detection engine
    detector.sync_rules_from_db()
    return jsonify({"success": True, "message": f"Rule {res} approved and hot-reloaded into detection engine.", "rule_id": res})

@app.route("/api/rules/toggle", methods=["POST"])
def toggle_rule():
    payload = request.get_json(silent=True) or {}
    rule_id = payload.get("rule_id")
    status = payload.get("status", "INACTIVE")
    if not rule_id:
        return jsonify({"success": False, "error": "rule_id is required"}), 400

    db.set_rule_status(rule_id, status)
    detector.sync_rules_from_db()
    return jsonify({"success": True, "message": f"Rule {rule_id} status updated to {status}."})

@app.route("/api/rules/audit", methods=["GET"])
def get_audit_logs():
    logs = db.get_rule_audit_logs(limit=50)
    return jsonify({"success": True, "count": len(logs), "data": logs})

if not IS_DEMO_MODE and not SNIFFER_RUNNING:
    SNIFFER_RUNNING = True
    SNIFFER_THREAD = threading.Thread(target=sniffer_worker, daemon=True)
    SNIFFER_THREAD.start()

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

@app.route("/api/demo/seed", methods=["POST"])
def seed_demo_data():
    ts = time.time()
    batch_size = 52480
    pkts = []
    
    for i in range(batch_size):
        src = f"192.168.1.{random.randint(10, 250)}"
        dst = f"192.168.1.{random.randint(2, 5)}"
        sport = random.choice([80, 443, 22, 53, 3389] + list(range(49152, 65535, 17)))
        dport = random.choice([80, 443, 22, 53, 3389])
        proto = random.choice(["TCP", "UDP"])
        length = random.randint(40, 1500)
        
        pkts.append({
            "ts": ts - (batch_size - i) * 0.05,
            "source_ip": src,
            "source_port": sport,
            "destination_ip": dst,
            "destination_port": dport,
            "protocol": proto,
            "length": length
        })

    db.insert_network_events_batch(pkts)

    demo_alerts = [
        {
            "ts": ts - 10,
            "alert_type": "DLP_VIOLATION",
            "severity": "CRITICAL",
            "threat_score": 95,
            "source_ip": "192.168.1.140",
            "source_port": 54321,
            "destination_ip": "192.168.1.5",
            "destination_port": 80,
            "protocol": "TCP",
            "description": "DLP Violation (SSN): Found unencrypted sensitive data matching XXX-XX-6789",
            "status": "NEW"
        },
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
    app.run(host="0.0.0.0", port=5050, debug=True)  # nosec B104 B201
