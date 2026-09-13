import sqlite3
import time
from contextlib import contextmanager

# SQLite database table templates layout schemas
SCHEMA_SQL = """
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

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(threat_score);
CREATE INDEX IF NOT EXISTS idx_network_ts ON network_events(ts);
"""

class Database:
    # Database helper object that auto-initializes the schema tables
    def __init__(self, db_path):
        self.db_path = db_path
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    # Helper manager to safely create SQLite connections with context handling
    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # Save security alerts to the database
    def insert_alert(self, alert):
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

    # Retrieve filtered alerts history based on query parameters
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

    # Fetch priority threats sorted by threat score in descending order
    def get_ranked_alerts(self, limit=100):
        sql = "SELECT * FROM alerts ORDER BY threat_score DESC, ts DESC LIMIT ?"
        with self._connect() as conn:
            res = conn.execute(sql, [limit]).fetchall()
        return [dict(r) for r in res]

    # Log authentication events to the database
    def insert_login_event(self, evt):
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

    # Save general packet metadata details to the database
    def insert_network_event(self, pkt):
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

    # Perform batch insertion for fast mock network data loading
    def insert_network_events_batch(self, pkts):
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

    # Retrieve recent network events to update the UI dashboard feed
    def get_live_network(self, limit=50):
        sql = "SELECT * FROM network_events ORDER BY ts DESC LIMIT ?"
        with self._connect() as conn:
            res = conn.execute(sql, [limit]).fetchall()
        return [dict(r) for r in res]

    # Wipe all captured data and stored alerts for a fresh system reset
    def reset_all(self):
        with self._connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM login_events")
            conn.execute("DELETE FROM network_events")

    # Calculate aggregate statistics for the dashboard UI cards
    def get_stats(self):
        with self._connect() as conn:
            total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            total_events = conn.execute("SELECT COUNT(*) c FROM network_events").fetchone()["c"] + \
                           conn.execute("SELECT COUNT(*) c FROM login_events").fetchone()["c"]
            
            avg_score = conn.execute("SELECT AVG(threat_score) a FROM alerts").fetchone()["a"] or 0
            max_score = conn.execute("SELECT MAX(threat_score) m FROM alerts").fetchone()["m"] or 0
            
            levels = {}
            for row in conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"):
                levels[row["severity"]] = row["c"]

        return {
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
