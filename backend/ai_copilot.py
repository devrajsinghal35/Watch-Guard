import json
import random
import os

try:
    import google.generativeai as genai
except ImportError:
    genai = None

class AICopilot:
    def __init__(self):
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY")
        if self.gemini_api_key and genai:
            genai.configure(api_key=self.gemini_api_key)
            self.gemini_model = genai.GenerativeModel('gemini-1.5-flash', generation_config={"response_mime_type": "application/json"})
        else:
            self.gemini_model = None

    def get_service_name(self, port):
        port = int(port) if port else 0
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 139: "NetBIOS", 443: "HTTPS",
            3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, f"Custom Port {port}")

    def analyze_incident(self, alert_data):
        if self.gemini_model:
            return self._call_gemini_api(alert_data)
        
        return self._run_dynamic_simulation(alert_data)

    def _get_prompt(self, alert_data):
        return f"""
        You are a senior SOC analyst for Watch Guard. Analyze the following network security alert and provide a structured JSON remediation playbook.

        Alert Details:
        - Type: {alert_data.get('alert_type')}
        - Source IP: {alert_data.get('source_ip')}
        - Destination: {alert_data.get('destination_ip')}:{alert_data.get('destination_port')}
        - Protocol: {alert_data.get('protocol')}
        - Severity/Score: {alert_data.get('severity')} ({alert_data.get('threat_score')}/100)
        - Description: {alert_data.get('description')}

        Return EXACTLY a raw JSON object (no markdown, no backticks) with the following exact keys:
        {{
            "summary": "Short 1-sentence executive summary including the MITRE ATT&CK ID.",
            "root_cause": "1-2 sentences explaining what the attacker is doing and the vulnerability.",
            "remediation_steps": ["step 1", "step 2", "step 3"],
            "recommended_firewall_rule": "A specific Linux iptables command to mitigate the threat (using the actual IPs and ports).",
            "confidence_score": 0.95
        }}
        """

    def _call_gemini_api(self, alert_data):
        prompt = self._get_prompt(alert_data)
        model_candidates = [
            'gemini-flash-latest',
            'gemini-1.5-flash',
            'gemini-2.0-flash',
            'gemini-1.5-pro'
        ]
        
        for model_name in model_candidates:
            try:
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(prompt)
                raw_text = response.text.strip()
                if raw_text.startswith("```"):
                    lines = raw_text.splitlines()
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].startswith("```"):
                        lines = lines[:-1]
                    raw_text = "\n".join(lines).strip()

                result_json = json.loads(raw_text)
                return {
                    "summary": result_json.get("summary", "Analysis completed."),
                    "root_cause": result_json.get("root_cause", "N/A"),
                    "remediation_steps": result_json.get("remediation_steps", []),
                    "recommended_firewall_rule": result_json.get("recommended_firewall_rule", ""),
                    "confidence_score": float(result_json.get("confidence_score", 0.95))
                }
            except Exception as e:
                print(f"Gemini API model {model_name} attempt error: {e}")
                continue

        return self._run_dynamic_simulation(alert_data)

    def _run_dynamic_simulation(self, alert_data):
        alert_type = alert_data.get('alert_type', 'UNKNOWN')
        source_ip = alert_data.get('source_ip', '0.0.0.0')  # nosec B104
        dest_ip = alert_data.get('destination_ip', '192.168.1.1')
        dest_port = alert_data.get('destination_port', 0)
        protocol = alert_data.get('protocol', 'TCP')
        description = alert_data.get('description', '')
        score = alert_data.get('threat_score', 50)
        
        service_target = self.get_service_name(dest_port)
        confidence = round(min(0.99, (score / 100) + random.uniform(0.01, 0.1)), 2)

        if alert_type == "BRUTE_FORCE":
            mitre_id = "T1110.001"
            summary = f"Detected sustained credential stuffing (MITRE {mitre_id}) originating from {source_ip}, actively targeting {service_target} on {dest_ip}."
            root_cause = f"Automated botnet or script attempting to bypass {service_target} authentication via dictionary attacks on port {dest_port}. High likelihood of account compromise if no lockout policies are enforced."
            remediation_steps = [
                f"Immediately drop active connections from {source_ip} to {dest_ip}:{dest_port}.",
                f"Review {service_target} authentication logs on {dest_ip} to identify potentially compromised accounts.",
                f"Enforce rate-limiting on port {dest_port} (maximum 3 failed attempts per minute).",
                f"Disable password-based authentication for {service_target} and enforce MFA/key-based access."
            ]
            recommended_firewall_rule = f"sudo iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -j DROP"

        elif alert_type == "SYN_FLOOD":
            mitre_id = "T1498.001"
            summary = f"Volumetric {protocol} SYN Flood (MITRE {mitre_id}) detected from {source_ip} targeting {dest_ip}:{dest_port} ({service_target})."
            root_cause = f"Denial-of-Service attempt from {source_ip}. Rapid unacknowledged SYN packets on port {dest_port} risk exhausting socket buffers on {dest_ip}."
            remediation_steps = [
                f"Enable TCP SYN cookies on {dest_ip} via sysctl (net.ipv4.tcp_syncookies = 1).",
                f"Rate limit incoming {protocol} SYN packets from {source_ip} at edge perimeter.",
                f"Implement connection rate limiting and drop excess SYN requests."
            ]
            recommended_firewall_rule = f"sudo iptables -I INPUT -p tcp -s {source_ip} --dport {dest_port} --syn -m limit --limit 1/s -j ACCEPT\nsudo iptables -A INPUT -p tcp -s {source_ip} --dport {dest_port} --syn -j DROP"

        elif alert_type == "PORT_SCAN":
            mitre_id = "T1046"
            summary = f"Active network reconnaissance (MITRE {mitre_id}) by {source_ip}, scanning multiple ports on {dest_ip}."
            root_cause = f"Host {source_ip} is probing ports to identify active listening services on {dest_ip}, typically preceding exploitation."
            remediation_steps = [
                f"Block scanning host {source_ip} at perimeter firewall.",
                f"Review exposed attack surface on {dest_ip} and close inactive ports.",
                f"Correlate {source_ip} across SIEM logs for subsequent application-layer probes."
            ]
            recommended_firewall_rule = f"sudo iptables -A INPUT -s {source_ip} -j REJECT --reject-with icmp-host-prohibited"

        elif alert_type == "DLP_VIOLATION":
            cat_match = "Sensitive Data"
            if "CREDIT_CARD" in description: cat_match = "Credit Card (PCI) Data"
            elif "SSN" in description: cat_match = "SSN (PII) Data"
            elif "API_KEY" in description: cat_match = "API Credentials/Tokens"
            elif "INTERNAL_HEADER" in description: cat_match = "Confidential Internal Headers"

            summary = f"Critical Data Loss Prevention (DLP) violation: unencrypted {cat_match} detected in transit from {source_ip} to {dest_ip} over {protocol}."
            root_cause = f"Plaintext transmission of {cat_match} from {source_ip}. Violates data confidentiality and compliance policies."
            remediation_steps = [
                f"Sever active {protocol} connection between {source_ip} and {dest_ip} to halt exfiltration.",
                f"Inspect application service on {source_ip} responsible for unencrypted transmission.",
                f"Enforce TLS 1.2+ encryption for all inbound and outbound endpoints.",
                f"If credentials or tokens were exposed, rotate affected keys immediately."
            ]
            recommended_firewall_rule = f"sudo iptables -I OUTPUT -d {dest_ip} -p {protocol.lower()} -j REJECT\nsudo iptables -I INPUT -s {source_ip} -j DROP"

        else:
            summary = f"Anomalous network behavior detected involving {source_ip} and {dest_ip}."
            root_cause = "Unclassified traffic pattern flagged by telemetry threshold."
            remediation_steps = [
                f"Inspect ongoing traffic originating from {source_ip}.",
                f"Review network packet captures directed toward {dest_ip}."
            ]
            recommended_firewall_rule = f"sudo tcpdump -i any host {source_ip}"

        return {
            "summary": summary,
            "root_cause": root_cause,
            "remediation_steps": remediation_steps,
            "recommended_firewall_rule": recommended_firewall_rule,
            "confidence_score": confidence
        }

ai_copilot = AICopilot()
