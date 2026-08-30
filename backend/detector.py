import time

# Threshold parameters defining when detection alerts are triggered
PORT_SCAN_LIMIT = 10
PORT_SCAN_SEC = 10

SYN_FLOOD_LIMIT = 50
SYN_FLOOD_SEC = 5

BRUTE_FORCE_LIMIT = 5
BRUTE_FORCE_SEC = 180

# Default deterministic threat/risk scores for different alert types
SCORES = {
    "PORT_SCAN": 70,
    "BRUTE_FORCE": 80,
    "SYN_FLOOD": 90,
    "NORMAL": 10,
}

# Severity mapping corresponding to each alert type
SEVERITIES = {
    "PORT_SCAN": "HIGH",
    "BRUTE_FORCE": "HIGH",
    "SYN_FLOOD": "CRITICAL",
    "NORMAL": "LOW",
}

# Returns the direct threat score based on the alert type
def score_threat(alert_name):
    return SCORES.get(alert_name, 20)

# Helper function to classify severity label from the threat score value
def get_severity(score_val):
    if score_val >= 90:
        return "CRITICAL"
    if score_val >= 70:
        return "HIGH"
    if score_val >= 40:
        return "MEDIUM"
    return "LOW"

class DetectionEngine:
    # Initialize history buffer arrays for sliding window comparisons
    def __init__(self):
        self.packets = []
        self.logins = []

    # Analyzes each new packet and runs port scan and syn flood detection rules
    def process_packet(self, pkt):
        now = pkt.get("ts", time.time())
        pkt["ts"] = now
        self.packets.append(pkt)

        # Remove packets older than 15 seconds from the memory buffer
        self.packets = [p for p in self.packets if now - p["ts"] <= 15]

        found_alerts = []
        sip = pkt.get("source_ip")
        dip = pkt.get("destination_ip")

        if not sip:
            return found_alerts

        # RULE 1: Port Scan checks - Check if a source IP has scanned multiple ports
        matching_pkts = [
            p for p in self.packets
            if p.get("source_ip") == sip and now - p["ts"] <= PORT_SCAN_SEC
        ]
        unique_ports = {p.get("destination_port") for p in matching_pkts if p.get("destination_port")}
        
        if len(unique_ports) >= PORT_SCAN_LIMIT:
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

        # RULE 2: SYN Flood checks - Check for high-rate SYN traffic targeting destination IP/ports
        syn_pkts = [
            p for p in matching_pkts
            if p.get("protocol") == "TCP" and "S" in str(p.get("flags", "")) and "A" not in str(p.get("flags", ""))
            and now - p["ts"] <= SYN_FLOOD_SEC
        ]
        if len(syn_pkts) >= SYN_FLOOD_LIMIT:
            score = SCORES["SYN_FLOOD"]
            target_p = pkt.get("destination_port", 443)
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

        return found_alerts

    # Evaluates login attempt events to trigger brute force alerts
    def process_login_event(self, login_evt):
        now = login_evt.get("ts", time.time())
        login_evt["ts"] = now
        self.logins.append(login_evt)

        # Remove historical login records older than the brute force window
        self.logins = [e for e in self.logins if now - e["ts"] <= BRUTE_FORCE_SEC]

        found_alerts = []
        # Analyze brute force scenarios only for failed login attempts
        if login_evt.get("status") == "failed":
            sip = login_evt.get("source_ip")
            srv = login_evt.get("service", "SSH")
            failures = [
                e for e in self.logins
                if e.get("source_ip") == sip and e.get("service") == srv
                and e.get("status") == "failed" and now - e["ts"] <= BRUTE_FORCE_SEC
            ]

            # Generate brute force alert if failure threshold is met
            if len(failures) >= BRUTE_FORCE_LIMIT:
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
