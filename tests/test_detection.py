import time
from backend.detector import DetectionEngine, score_threat, get_severity

def test_port_scan_detection():
    engine = DetectionEngine()
    sip = "192.168.1.50"
    dip = "192.168.1.10"
    now = time.time()

    triggered = []
    for port in range(1, 11):
        pkt = {
            "ts": now,
            "source_ip": sip,
            "source_port": 50000 + port,
            "destination_ip": dip,
            "destination_port": port,
            "protocol": "TCP",
            "flags": "S",
            "length": 60,
        }
        triggered.extend(engine.process_packet(pkt))

    assert len(triggered) > 0
    alert = triggered[-1]
    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["severity"] == "HIGH"
    assert alert["threat_score"] == 70
    assert alert["source_ip"] == sip

def test_syn_flood_detection():
    engine = DetectionEngine()
    sip = "192.168.1.100"
    dip = "192.168.1.20"
    now = time.time()

    triggered = []
    for _ in range(50):
        pkt = {
            "ts": now,
            "source_ip": sip,
            "source_port": 49152,
            "destination_ip": dip,
            "destination_port": 443,
            "protocol": "TCP",
            "flags": "S",
            "length": 54,
        }
        triggered.extend(engine.process_packet(pkt))

    assert len(triggered) > 0
    alert = triggered[-1]
    assert alert["alert_type"] == "SYN_FLOOD"
    assert alert["severity"] == "CRITICAL"
    assert alert["threat_score"] == 90
    assert alert["source_ip"] == sip

def test_brute_force_detection():
    engine = DetectionEngine()
    sip = "192.168.1.75"
    now = time.time()

    triggered = []
    for _ in range(5):
        evt = {
            "ts": now,
            "source_ip": sip,
            "username": "root",
            "service": "SSH",
            "port": 22,
            "status": "failed",
        }
        triggered.extend(engine.process_login_event(evt))

    assert len(triggered) > 0
    alert = triggered[-1]
    assert alert["alert_type"] == "BRUTE_FORCE"
    assert alert["severity"] == "HIGH"
    assert alert["threat_score"] == 80
    assert alert["source_ip"] == sip

def test_score_and_severity_helper():
    assert score_threat("SYN_FLOOD") == 90
    assert score_threat("PORT_SCAN") == 70
    assert score_threat("BRUTE_FORCE") == 80
    assert get_severity(90) == "CRITICAL"
    assert get_severity(70) == "HIGH"
    assert get_severity(10) == "LOW"
