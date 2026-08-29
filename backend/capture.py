import time
import logging

# Logger setup taaki debug logs print ho sakein
logger = logging.getLogger("sentry.capture")

class PacketCapturer:
    # Constructor jo sniffer state initialize karta hai
    def __init__(self, callback=None):
        self.callback = callback
        self.running = False

    # Yeh function single network packet ko capture/sniff karta hai aur useful metadata filter karta hai
    def sniff_packet(self):
        try:
            # Scapy se sniff aur layers import kar rahe hain
            from scapy.all import sniff, IP, TCP, UDP
            # Ek packet capture karenge 1.0 second ke timeout ke saath
            pkts = sniff(count=1, timeout=1.0)
            if not pkts:
                return None
            
            pkt = pkts[0]
            curr_time = time.time()

            # Agar IP layer present hai toh details nikalenge
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                # Protocol identify kar rahe hain: TCP, UDP ya general IP
                protocol = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IP")
                # Source aur Destination ports parse kar rahe hain
                sport = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (int(pkt[UDP].sport) if pkt.haslayer(UDP) else 0)
                dport = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (int(pkt[UDP].dport) if pkt.haslayer(UDP) else 0)
                # TCP flags check kar rahe hain agar TCP connection hai
                tcp_flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else ""
                
                # Sniffed packet details return kar rahe hain dashboard feed ke liye
                return {
                    "ts": curr_time,
                    "source_ip": ip_layer.src,
                    "source_port": sport,
                    "destination_ip": ip_layer.dst,
                    "destination_port": dport,
                    "protocol": protocol,
                    "flags": tcp_flags,
                    "length": len(pkt),
                }
        except Exception as err:
            # Error log karenge bina crash kiye fallback control ke liye
            logger.debug(f"Packet sniffing issue: {err}")
            return None
        return None
