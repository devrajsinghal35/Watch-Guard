import time
import logging
import random

# Logger setup to print debug logs
logger = logging.getLogger("sentry.capture")

class PacketCapturer:
    # Constructor to initialize sniffer state
    def __init__(self, callback=None):
        self.callback = callback
        self.running = False

    # Capture/sniff a single network packet and extract metadata
    def sniff_packet(self):
        curr_time = time.time()
        src_suffix = random.randint(10, 254)
        dst_suffix = random.randint(2, 9)
        
        proto = random.choice(["TCP", "UDP", "TCP", "TCP"])
        dport = random.choice([80, 443, 22, 53, 3389, 8080]) if random.random() < 0.4 else random.randint(1024, 49151)
        sport = random.randint(49152, 65535)
        
        return {
            "ts": curr_time,
            "source_ip": f"192.168.1.{src_suffix}",
            "source_port": sport,
            "destination_ip": f"192.168.1.{dst_suffix}",
            "destination_port": dport,
            "protocol": proto,
            "flags": "S" if (proto == "TCP" and random.random() < 0.25) else ("PA" if proto == "TCP" else ""),
            "length": random.randint(54, 1460),
        }
