import time
import logging
import random

# Mock payloads for network simulation
BENIGN_PAYLOADS = [
    "GET /index.html HTTP/1.1\r\nHost: example.com",
    "GET /static/css/style.css HTTP/1.1\r\nHost: myapp.local",
    "POST /api/v1/telemetry HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}",
    "GET /images/logo.png HTTP/1.1\r\nHost: cdn.internal",
    "DNS Query: api.github.com A?",
    "TLS Client Hello - cipher suites: TLS_AES_128_GCM_SHA256",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "GET /healthz HTTP/1.1\r\nHost: k8s.local",
]

DLP_PAYLOADS = [
    "Found user data: John Doe, SSN: 123-45-6789", # DLP trigger
    "POST /login HTTP/1.1\r\nAuthorization: Bearer mysecrettoken1234567890abcdef" # DLP trigger
]

# Logger setup to print debug logs
logger = logging.getLogger("watchguard.capture")

class PacketCapturer:
    # Constructor to initialize sniffer state
    def __init__(self, callback=None):
        self.callback = callback
        self.running = False

    # Capture/sniff a single network packet and extract metadata
    def sniff_packet(self):
        curr_time = time.time()
        r = random.random()
        
        # 1. Simulate Port Scan behavior from 192.168.1.105 (25% of traffic)
        if r < 0.25:
            src_ip = "192.168.1.105"
            dst_ip = "192.168.1.4"
            dport = random.randint(1, 1024) # Scanning random ports
            proto = "TCP"
            flags = "S"
            payload = ""
        # 2. Simulate SYN Flood behavior from 192.168.1.188 (25% of traffic)
        elif r < 0.50:
            src_ip = "192.168.1.188"
            dst_ip = "192.168.1.3"
            dport = 443
            proto = "TCP"
            flags = "S"
            payload = ""
        # 3. Simulate DLP Exfiltration occasionally (0.5% chance)
        elif r < 0.505:
            src_ip = f"192.168.1.{random.randint(50, 99)}"
            dst_ip = f"192.168.1.{random.randint(2, 5)}"
            dport = 80
            proto = "TCP"
            flags = "PA"
            payload = random.choice(DLP_PAYLOADS)
        # 4. Normal benign traffic (50% of traffic)
        else:
            src_ip = f"192.168.1.{random.randint(10, 254)}"
            dst_ip = f"192.168.1.{random.randint(2, 9)}"
            dport = random.choice([80, 443, 22, 53, 3389, 8080]) if random.random() < 0.4 else random.randint(1024, 49151)
            proto = random.choice(["TCP", "UDP", "TCP", "TCP"])
            flags = "PA" if proto == "TCP" else ""
            payload = random.choice(BENIGN_PAYLOADS) if random.random() < 0.05 else ""

        sport = random.randint(49152, 65535)
        
        return {
            "ts": curr_time,
            "source_ip": src_ip,
            "source_port": sport,
            "destination_ip": dst_ip,
            "destination_port": dport,
            "protocol": proto,
            "flags": flags,
            "length": random.randint(54, 1460),
            "payload": payload,
        }
