import sqlite3
import time
from contextlib import contextmanager

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA cache_size=-64000;

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    threat_score INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL DEFAULT 0,
    destination_ip TEXT NOT NULL,
    destination_port INTEGER NOT NULL DEFAULT 80,
    protocol TEXT NOT NULL DEFAULT 'TCP',
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW'
);

CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT 'SSH',
    port INTEGER NOT NULL DEFAULT 22,
    status TEXT NOT NULL DEFAULT 'failed'
);

CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_ip TEXT NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    length INTEGER NOT NULL
);

-- Adaptive Detection Rulebook Tables
CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    pattern TEXT NOT NULL,
    target_field TEXT NOT NULL DEFAULT 'payload',
    severity TEXT NOT NULL DEFAULT 'HIGH',
    threat_score INTEGER NOT NULL DEFAULT 75,
    description TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS candidate_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    pattern TEXT NOT NULL,
    target_field TEXT NOT NULL DEFAULT 'payload',
    severity TEXT NOT NULL DEFAULT 'HIGH',
    threat_score INTEGER NOT NULL DEFAULT 75,
    rationale TEXT NOT NULL,
    trigger_sample TEXT,
    validation_status TEXT NOT NULL DEFAULT 'PENDING',
    false_positive_rate REAL DEFAULT 0.0,
    created_at REAL NOT NULL,
    approved_by TEXT,
    approved_at REAL
);

CREATE TABLE IF NOT EXISTS rule_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    action TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    details TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'SYSTEM'
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(threat_score DESC, ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_network_ts ON network_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_login_ts ON login_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_rules_status ON detection_rules(status);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidate_rules(validation_status);
"""

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self._stats_cache = None
        self._stats_cache_time = 0
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=20.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def invalidate_stats_cache(self):
        self._stats_cache_time = 0

    def insert_alert(self, alert):
        self.invalidate_stats_cache()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO alerts
                   (ts, alert_type, severity, threat_score, source_ip, source_port,
                    destination_ip, destination_port, protocol, description, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.get("ts", time.time()),
                    alert["alert_type"],
                    alert["severity"],
                    int(alert["threat_score"]),
                    alert["source_ip"],
                    alert.get("source_port", 0),
                    alert.get("destination_ip", "192.168.1.1"),
                    alert.get("destination_port", 80),
                    alert.get("protocol", "TCP"),
                    alert["description"],
                    alert.get("status", "NEW"),
                ),
            )
            return cur.lastrowid

    def get_alerts(self, limit=100, alert_type=None, severity=None):
        sql = "SELECT * FROM alerts WHERE 1=1"
        args = []
        if alert_type:
            sql += " AND alert_type = ?"
            args.append(alert_type)
        if severity:
            sql += " AND severity = ?"
            args.append(severity.upper())
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)

        with self._connect() as conn:
            res = conn.execute(sql, args).fetchall()
        return [dict(r) for r in res]

    def get_ranked_alerts(self, limit=100):
        sql = "SELECT * FROM alerts ORDER BY threat_score DESC, ts DESC LIMIT ?"
        with self._connect() as conn:
            res = conn.execute(sql, [limit]).fetchall()
        return [dict(r) for r in res]

    def insert_login_event(self, evt):
        self.invalidate_stats_cache()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO login_events (ts, source_ip, username, service, port, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    evt.get("ts", time.time()),
                    evt["source_ip"],
                    evt["username"],
                    evt.get("service", "SSH"),
                    evt.get("port", 22),
                    evt.get("status", "failed"),
                ),
            )

    def get_login_history_by_ip(self, ip_address, limit=1000):
        sql = "SELECT * FROM login_events WHERE source_ip = ? ORDER BY ts ASC LIMIT ?"
        with self._connect() as conn:
            res = conn.execute(sql, [ip_address, limit]).fetchall()
        return [dict(r) for r in res]

    def insert_network_event(self, pkt):
        self.invalidate_stats_cache()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO network_events (ts, source_ip, source_port, destination_ip, destination_port, protocol, length)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    pkt.get("ts", time.time()),
                    pkt["source_ip"],
                    pkt["source_port"],
                    pkt["destination_ip"],
                    pkt["destination_port"],
                    pkt["protocol"],
                    pkt.get("length", 64),
                ),
            )

    def insert_network_events_batch(self, pkts):
        if not pkts:
            return
        self.invalidate_stats_cache()
        with self._connect() as conn:
            conn.executemany(
                """INSERT INTO network_events (ts, source_ip, source_port, destination_ip, destination_port, protocol, length)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        p.get("ts", time.time()),
                        p["source_ip"],
                        p["source_port"],
                        p["destination_ip"],
                        p["destination_port"],
                        p["protocol"],
                        p.get("length", 64),
                    )
                    for p in pkts
                ]
            )

    def get_live_network(self, limit=50):
        sql = "SELECT * FROM network_events ORDER BY ts DESC LIMIT ?"
        with self._connect() as conn:
            res = conn.execute(sql, [limit]).fetchall()
        return [dict(r) for r in res]

    def reset_all(self):
        self.invalidate_stats_cache()
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM login_events")
            conn.execute("DELETE FROM network_events")

    def get_stats(self):
        now = time.time()
        if self._stats_cache and (now - self._stats_cache_time < 1.5):
            return self._stats_cache

        with self._connect() as conn:
            total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            raw_events = conn.execute("SELECT COUNT(*) c FROM network_events").fetchone()["c"] + \
                           conn.execute("SELECT COUNT(*) c FROM login_events").fetchone()["c"]
            total_events = raw_events
            
            avg_score = conn.execute("SELECT AVG(threat_score) a FROM alerts").fetchone()["a"] or 0
            max_score = conn.execute("SELECT MAX(threat_score) m FROM alerts").fetchone()["m"] or 0
            
            levels = {}
            for row in conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"):
                levels[row["severity"]] = row["c"]

        res = {
            "total_alerts": total_alerts,
            "total_events": total_events,
            "avg_threat_score": round(avg_score, 1),
            "max_threat_score": max_score,
            "threat_levels": {
                "LOW": levels.get("LOW", 0),
                "MEDIUM": levels.get("MEDIUM", 0),
                "HIGH": levels.get("HIGH", 0),
                "CRITICAL": levels.get("CRITICAL", 0),
            },
        }
        self._stats_cache = res
        self._stats_cache_time = now
        return res

    # --- Adaptive Rulebook Management ---

    def get_active_rules(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM detection_rules WHERE status = 'ACTIVE' ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]

    def get_all_rules(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM detection_rules ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def insert_detection_rule(self, rule):
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO detection_rules
                   (rule_id, name, category, pattern, target_field, severity, threat_score, description, version, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule["rule_id"],
                    rule["name"],
                    rule.get("category", "CUSTOM"),
                    rule["pattern"],
                    rule.get("target_field", "payload"),
                    rule.get("severity", "HIGH"),
                    int(rule.get("threat_score", 75)),
                    rule.get("description", ""),
                    int(rule.get("version", 1)),
                    rule.get("status", "ACTIVE"),
                    rule.get("created_at", now),
                    now
                )
            )
            conn.execute(
                """INSERT INTO rule_audit_log (ts, action, rule_id, version, details, actor)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (now, "UPSERT", rule["rule_id"], int(rule.get("version", 1)), f"Rule {rule['name']} upserted.", rule.get("actor", "SYSTEM"))
            )

    def set_rule_status(self, rule_id, status, actor="SOC_ANALYST"):
        now = time.time()
        with self._connect() as conn:
            conn.execute("UPDATE detection_rules SET status = ?, updated_at = ? WHERE rule_id = ?", (status, now, rule_id))
            conn.execute(
                """INSERT INTO rule_audit_log (ts, action, rule_id, version, details, actor)
                   VALUES (?, ?, ?, (SELECT version FROM detection_rules WHERE rule_id = ?), ?, ?)""",
                (now, f"STATUS_{status}", rule_id, rule_id, f"Rule {rule_id} status changed to {status}.", actor)
            )

    def rollback_rule(self, rule_id, target_version, pattern, actor="SOC_ANALYST"):
        now = time.time()
        with self._connect() as conn:
            conn.execute("UPDATE detection_rules SET pattern = ?, version = ?, updated_at = ? WHERE rule_id = ?",
                         (pattern, target_version, now, rule_id))
            conn.execute(
                """INSERT INTO rule_audit_log (ts, action, rule_id, version, details, actor)
                   VALUES (?, 'ROLLBACK', ?, ?, ?, ?)""",
                (now, rule_id, target_version, f"Rolled back {rule_id} to v{target_version}", actor)
            )

    def insert_candidate_rule(self, candidate):
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO candidate_rules
                   (candidate_id, name, category, pattern, target_field, severity, threat_score, rationale, trigger_sample, validation_status, false_positive_rate, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    candidate["candidate_id"],
                    candidate["name"],
                    candidate.get("category", "ANOMALY_CANDIDATE"),
                    candidate["pattern"],
                    candidate.get("target_field", "payload"),
                    candidate.get("severity", "MEDIUM"),
                    int(candidate.get("threat_score", 65)),
                    candidate.get("rationale", ""),
                    candidate.get("trigger_sample", ""),
                    candidate.get("validation_status", "PENDING"),
                    float(candidate.get("false_positive_rate", 0.0)),
                    now
                )
            )

    def get_candidate_rules(self, status=None):
        sql = "SELECT * FROM candidate_rules"
        args = []
        if status:
            sql += " WHERE validation_status = ?"
            args.append(status)
        sql += " ORDER BY id DESC"
        with self._connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def approve_candidate_rule(self, candidate_id, approver="SOC_LEAD"):
        now = time.time()
        with self._connect() as conn:
            cand = conn.execute("SELECT * FROM candidate_rules WHERE candidate_id = ?", (candidate_id,)).fetchone()
            if not cand:
                return False, "Candidate rule not found"
            cand_dict = dict(cand)
            
            # Promote to detection_rules
            rule_id = f"RULE_{cand_dict['candidate_id']}"
            conn.execute(
                """INSERT OR REPLACE INTO detection_rules
                   (rule_id, name, category, pattern, target_field, severity, threat_score, description, version, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'ACTIVE', ?, ?)""",
                (
                    rule_id,
                    cand_dict["name"],
                    cand_dict["category"],
                    cand_dict["pattern"],
                    cand_dict["target_field"],
                    cand_dict["severity"],
                    cand_dict["threat_score"],
                    f"Promoted from candidate: {cand_dict['rationale']}",
                    now,
                    now
                )
            )
            conn.execute("UPDATE candidate_rules SET validation_status = 'APPROVED', approved_by = ?, approved_at = ? WHERE candidate_id = ?",
                         (approver, now, candidate_id))
            conn.execute(
                """INSERT INTO rule_audit_log (ts, action, rule_id, version, details, actor)
                   VALUES (?, 'PROMOTE_CANDIDATE', ?, 1, ?, ?)""",
                (now, rule_id, f"Candidate {candidate_id} approved and activated as {rule_id}.", approver)
            )
            return True, rule_id

    def get_rule_audit_logs(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM rule_audit_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

