import json
import random
import os

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

class AICopilot:
    def __init__(self):
        # Initialize OpenAI client if API key is available
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.client = OpenAI(api_key=self.api_key) if self.api_key and OpenAI else None

    def get_service_name(self, port):
        port = int(port) if port else 0
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 139: "NetBIOS", 443: "HTTPS",
            3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, f"Custom Port {port}")

    def analyze_incident(self, alert_data):
        """
        Analyzes the incident using OpenAI API if a key is provided, otherwise falls back
        to the highly contextual dynamic simulation.
        """
        # If we have an OpenAI API key, use the real LLM!
        if self.client:
            return self._call_openai_api(alert_data)
        
        # Otherwise, fall back to our advanced deterministic simulation
        return self._run_dynamic_simulation(alert_data)

    def _call_openai_api(self, alert_data):
        prompt = f"""
        You are a senior SOC AI Analyst for Honeywell Watch-Guard. Analyze the following network security alert and provide a structured JSON remediation playbook.

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

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini", # Fast, cost-effective, high quality
                messages=[
                    {"role": "system", "content": "You are a cyber security expert. Always return raw valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                response_format={ "type": "json_object" }
            )
            
            result_json = json.loads(response.choices[0].message.content)
            # Ensure all required keys exist
            return {
                "summary": result_json.get("summary", "AI Analysis failed to generate summary."),
                "root_cause": result_json.get("root_cause", "N/A"),
                "remediation_steps": result_json.get("remediation_steps", []),
                "recommended_firewall_rule": result_json.get("recommended_firewall_rule", ""),
                "confidence_score": float(result_json.get("confidence_score", 0.90))
            }
        except Exception as e:
            print(f"OpenAI API Error: {e}")
            # If the API fails for any reason (rate limit, etc), fall back to simulation
            return self._run_dynamic_simulation(alert_data)

    def _run_dynamic_simulation(self, alert_data):
        alert_type = alert_data.get('alert_type', 'UNKNOWN')
        source_ip = alert_data.get('source_ip', '0.0.0.0')
        dest_ip = alert_data.get('destination_ip', '192.168.1.1')
        dest_port = alert_data.get('destination_port', 0)
        protocol = alert_data.get('protocol', 'TCP')
        description = alert_data.get('description', '')
        score = alert_data.get('threat_score', 50)
        
        service_target = self.get_service_name(dest_port)
        confidence = round(min(0.99, (score / 100) + random.uniform(0.01, 0.1)), 2)

        if alert_type == "BRUTE_FORCE":
            mitre_id = "T1110.001"
            summary = f"(Simulated) Detected sustained credential stuffing (MITRE {mitre_id}) originating from {source_ip}, actively targeting the {service_target} service on host {dest_ip}."
            root_cause = f"Automated botnet or script attempting to bypass {service_target} authentication via dictionary attacks on port {dest_port}. High likelihood of account compromise if no lockout policies are enforced."
            remediation_steps = [
                f"Immediately drop all active connections from {source_ip} to {dest_ip}:{dest_port}.",
                f"Review {service_target} authentication logs on {dest_ip} to identify if any accounts were successfully compromised.",
                f"Enforce strict rate-limiting (e.g., max 3 attempts per minute) on port {dest_port}.",
                f"Consider disabling password-based authentication for {service_target} and mandate MFA."
            ]
            recommended_firewall_rule = f"sudo iptables -A INPUT -s {source_ip} -p {protocol.lower()} --dport {dest_port} -j DROP"

        elif alert_type == "SYN_FLOOD":
            mitre_id = "T1498.001"
            summary = f"(Simulated) Volumetric {protocol} SYN Flood (MITRE {mitre_id}) detected from {source_ip} targeting {dest_ip}:{dest_port} ({service_target})."
            root_cause = f"Attacker at {source_ip} is attempting a resource exhaustion Denial-of-Service (DoS) attack. The influx of half-open TCP connections on port {dest_port} threatens to consume all available socket buffers on {dest_ip}."
            remediation_steps = [
                f"Enable TCP SYN cookies on the target host {dest_ip} via sysctl (net.ipv4.tcp_syncookies = 1).",
                f"Rate limit incoming {protocol} SYN packets from {source_ip} at the edge router.",
                f"If the attack volume escalates, route {dest_ip} traffic through a cloud scrubbing center (e.g., Cloudflare/AWS Shield)."
            ]
            recommended_firewall_rule = f"sudo iptables -I INPUT -p tcp -s {source_ip} --dport {dest_port} --syn -m limit --limit 1/s -j ACCEPT\nsudo iptables -A INPUT -p tcp -s {source_ip} --dport {dest_port} --syn -j DROP"

        elif alert_type == "PORT_SCAN":
            mitre_id = "T1046"
            summary = f"(Simulated) Active network reconnaissance (MITRE {mitre_id}) by {source_ip}, scanning multiple ports on {dest_ip}."
            root_cause = f"The source IP {source_ip} is executing a rapid sweep to map open ports and vulnerable services on {dest_ip}. This is typically the precursor phase to a targeted exploit."
            remediation_steps = [
                f"Block the scanning IP {source_ip} at the perimeter firewall immediately.",
                f"Audit the exposed attack surface on {dest_ip} and ensure non-essential ports are closed.",
                f"Correlate {source_ip} across SIEM logs to see if it has initiated any subsequent application-layer exploits."
            ]
            recommended_firewall_rule = f"sudo iptables -A INPUT -s {source_ip} -j REJECT --reject-with icmp-host-prohibited"

        elif alert_type == "DLP_VIOLATION":
            cat_match = "Sensitive Data"
            if "CREDIT_CARD" in description: cat_match = "Credit Card (PCI) Data"
            elif "SSN" in description: cat_match = "SSN (PII) Data"
            elif "API_KEY" in description: cat_match = "API Credentials/Tokens"
            elif "INTERNAL_HEADER" in description: cat_match = "Confidential Internal Headers"

            summary = f"(Simulated) Critical Data Loss Prevention (DLP) violation! Unencrypted {cat_match} was detected in transit from {source_ip} to {dest_ip} over {protocol}."
            root_cause = f"A vulnerability or misconfiguration on {source_ip} is leaking {cat_match} in plaintext. This severely violates data confidentiality and compliance standards (e.g., PCI-DSS, GDPR)."
            remediation_steps = [
                f"Immediately sever the active {protocol} connection between {source_ip} and {dest_ip} to halt exfiltration.",
                f"Investigate the application on {source_ip} responsible for transmitting plaintext {cat_match}.",
                f"Force TLS 1.2+ / HTTPS encryption for all traffic destined to {dest_ip}.",
                f"If API credentials were leaked, revoke and rotate them immediately across all secret managers."
            ]
            recommended_firewall_rule = f"sudo iptables -I OUTPUT -d {dest_ip} -p {protocol.lower()} -j REJECT\nsudo iptables -I INPUT -s {source_ip} -j DROP"

        else:
            summary = f"(Simulated) Anomalous network behavior detected involving {source_ip} and {dest_ip}."
            root_cause = "Unclassified network anomaly requiring manual SOC triage."
            remediation_steps = [
                f"Monitor traffic from {source_ip}.",
                f"Review packet captures targeting {dest_ip}."
            ]
            recommended_firewall_rule = f"# Monitor traffic\nsudo tcpdump -i any host {source_ip}"

        return {
            "summary": summary,
            "root_cause": root_cause,
            "remediation_steps": remediation_steps,
            "recommended_firewall_rule": recommended_firewall_rule,
            "confidence_score": confidence
        }

ai_copilot = AICopilot()
