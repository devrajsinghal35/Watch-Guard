import time
import re
from urllib.parse import unquote
from .dlp_engine import dlp_engine

PORT_SCAN_LIMIT = 5
PORT_SCAN_SEC = 10

SYN_FLOOD_LIMIT = 8
SYN_FLOOD_SEC = 5

BRUTE_FORCE_LIMIT = 3
BRUTE_FORCE_SEC = 180

SCORES = {
    "PORT_SCAN": 70,
    "BRUTE_FORCE": 80,
    "SYN_FLOOD": 90,
    "DLP_VIOLATION": 95,
    "NORMAL": 10,
}

SEVERITIES = {
    "PORT_SCAN": "HIGH",
    "BRUTE_FORCE": "HIGH",
    "SYN_FLOOD": "CRITICAL",
    "DLP_VIOLATION": "CRITICAL",
    "NORMAL": "LOW",
}


def score_threat(alert_name):
    return SCORES.get(alert_name, 20)


def get_severity(score_val):
    if score_val >= 90:
        return "CRITICAL"
    if score_val >= 70:
        return "HIGH"
    if score_val >= 40:
        return "MEDIUM"
    return "LOW"


class DetectionEngine:
    def __init__(self, db=None):
        self.db = db
        self.packets = []
        self.logins = []
        self.last_alert_time = {}
        self.dynamic_rules = {}
        if self.db:
            self.sync_rules_from_db()

    def reset(self):
        self.packets.clear()
        self.logins.clear()
        self.last_alert_time.clear()

    def process_packet(self, pkt):
        now = pkt.get("ts", time.time())
        pkt["ts"] = now
        self.packets.append(pkt)
        self.packets = [p for p in self.packets if now - p["ts"] <= 15]

        found_alerts = []
        sip = pkt.get("source_ip")
        dip = pkt.get("destination_ip")

        if not sip:
            return found_alerts

        matching_pkts = [
            p for p in self.packets
            if p.get("source_ip") == sip and now - p["ts"] <= PORT_SCAN_SEC
        ]

        # Port scan detection: requires SYN probes across distinct ports
        syn_scan_pkts = [
            p for p in matching_pkts
            if p.get("protocol") == "TCP" and "S" in str(p.get("flags", "")) and "A" not in str(p.get("flags", ""))
        ]
        unique_ports = {p.get("destination_port") for p in syn_scan_pkts if p.get("destination_port")}
        
        if len(unique_ports) >= PORT_SCAN_LIMIT:
            key = ("PORT_SCAN", sip)
            if now - self.last_alert_time.get(key, 0) >= PORT_SCAN_SEC:
                self.last_alert_time[key] = now
                score = SCORES["PORT_SCAN"]
                found_alerts.append({
                    "ts": now,
                    "alert_type": "PORT_SCAN",
                    "severity": SEVERITIES["PORT_SCAN"],
                    "threat_score": score,
                    "source_ip": sip,
                    "source_port": pkt.get("source_port", 0),
                    "destination_ip": dip or "192.168.1.1",
                    "destination_port": pkt.get("destination_port", 80),
                    "protocol": pkt.get("protocol", "TCP"),
                    "description": f"Port Scan: {len(unique_ports)} ports probed from {sip} within {PORT_SCAN_SEC}s.",
                })

        # SYN flood detection
        syn_pkts = [
            p for p in matching_pkts
            if p.get("protocol") == "TCP" and "S" in str(p.get("flags", "")) and "A" not in str(p.get("flags", ""))
            and now - p["ts"] <= SYN_FLOOD_SEC
        ]
        if len(syn_pkts) >= SYN_FLOOD_LIMIT:
            target_p = pkt.get("destination_port", 443)
            key = ("SYN_FLOOD", sip, target_p)
            if now - self.last_alert_time.get(key, 0) >= SYN_FLOOD_SEC:
                self.last_alert_time[key] = now
                score = SCORES["SYN_FLOOD"]
                found_alerts.append({
                    "ts": now,
                    "alert_type": "SYN_FLOOD",
                    "severity": SEVERITIES["SYN_FLOOD"],
                    "threat_score": score,
                    "source_ip": sip,
                    "source_port": pkt.get("source_port", 0),
                    "destination_ip": dip or "192.168.1.1",
                    "destination_port": target_p,
                    "protocol": "TCP",
                    "description": f"SYN Flood: High rate of TCP SYN packets ({len(syn_pkts)} pkts/{SYN_FLOOD_SEC}s) from {sip} targeting {dip}:{target_p}.",
                })

        # Deep packet inspection / DLP
        payload = pkt.get("payload", "")
        if payload:
            dlp_violations = dlp_engine.scan_payload(payload)
            if dlp_violations:
                score = SCORES["DLP_VIOLATION"]
                for v in dlp_violations:
                    key = ("DLP_VIOLATION", sip, v['category'])
                    if now - self.last_alert_time.get(key, 0) >= 30:
                        self.last_alert_time[key] = now
                        found_alerts.append({
                            "ts": now,
                            "alert_type": "DLP_VIOLATION",
                            "severity": SEVERITIES["DLP_VIOLATION"],
                            "threat_score": score,
                            "source_ip": sip,
                            "source_port": pkt.get("source_port", 0),
                            "destination_ip": dip or "192.168.1.1",
                            "destination_port": pkt.get("destination_port", 80),
                            "protocol": pkt.get("protocol", "TCP"),
                            "description": f"DLP Violation ({v['category']}): Found unencrypted sensitive data matching {v['redacted_match']}",
                        })

        # Dynamic / Adaptive Rule Evaluation
        dynamic_alerts = self.evaluate_dynamic_rules(pkt, now)
        found_alerts.extend(dynamic_alerts)

        return found_alerts

    def sync_rules_from_db(self):
        if not self.db:
            return
        try:
            active_rules = self.db.get_active_rules()
            new_rules = {}
            for r in active_rules:
                rid = r["rule_id"]
                pat_str = r["pattern"]
                try:
                    compiled = re.compile(pat_str, re.IGNORECASE)
                    new_rules[rid] = {**r, "_compiled": compiled}
                except Exception as e:
                    print(f"Failed to compile dynamic rule {rid}: {e}")
            self.dynamic_rules = new_rules
        except Exception as e:
            print(f"Error syncing dynamic rules: {e}")

    def evaluate_dynamic_rules(self, pkt, now):
        alerts = []
        if not self.dynamic_rules and self.db:
            self.sync_rules_from_db()

        sip = pkt.get("source_ip", "0.0.0.0")
        dip = pkt.get("destination_ip", "192.168.1.1")
        dport = pkt.get("destination_port", 80)
        proto = pkt.get("protocol", "TCP")

        for rid, r in self.dynamic_rules.items():
            raw_val = str(pkt.get(r.get("target_field", "payload"), ""))
            if not raw_val:
                continue

            target_val = unquote(raw_val)
            compiled = r.get("_compiled")
            if not compiled:
                continue

            match = compiled.search(target_val)
            if match:
                key = (rid, sip)
                if now - self.last_alert_time.get(key, 0) >= 15:
                    self.last_alert_time[key] = now
                    alerts.append({
                        "ts": now,
                        "alert_type": r.get("category", "CUSTOM_ALERT"),
                        "severity": r.get("severity", "HIGH"),
                        "threat_score": int(r.get("threat_score", 75)),
                        "source_ip": sip,
                        "source_port": pkt.get("source_port", 0),
                        "destination_ip": dip,
                        "destination_port": dport,
                        "protocol": proto,
                        "description": f"{r['name']}: {r.get('description', '')} [Matched: {match.group(0)[:40]}]",
                    })
        return alerts

    def process_login_event(self, login_evt):
        now = login_evt.get("ts", time.time())
        login_evt["ts"] = now
        self.logins.append(login_evt)
        self.logins = [e for e in self.logins if now - e["ts"] <= BRUTE_FORCE_SEC]

        found_alerts = []
        if login_evt.get("status") == "failed":
            sip = login_evt.get("source_ip")
            srv = login_evt.get("service", "SSH")
            failures = [
                e for e in self.logins
                if e.get("source_ip") == sip and e.get("service") == srv
                and e.get("status") == "failed" and now - e["ts"] <= BRUTE_FORCE_SEC
            ]

            if len(failures) >= BRUTE_FORCE_LIMIT:
                key = ("BRUTE_FORCE", sip, srv)
                if now - self.last_alert_time.get(key, 0) >= 60:
                    self.last_alert_time[key] = now
                    score = SCORES["BRUTE_FORCE"]
                    port_num = login_evt.get("port", 22)
                    user_name = login_evt.get("username", "root")
                    found_alerts.append({
                        "ts": now,
                        "alert_type": "BRUTE_FORCE",
                        "severity": SEVERITIES["BRUTE_FORCE"],
                        "threat_score": score,
                        "source_ip": sip,
                        "source_port": 0,
                        "destination_ip": "192.168.1.1",
                        "destination_port": port_num,
                        "protocol": "TCP",
                        "description": f"{srv} Brute Force: {len(failures)} failed logins from {sip} targeting '{user_name}' on port {port_num}.",
                    })

        return found_alerts
