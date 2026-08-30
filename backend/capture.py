import time
import logging

# Logger setup to print debug logs
logger = logging.getLogger("sentry.capture")

class PacketCapturer:
    # Constructor to initialize sniffer state
    def __init__(self, callback=None):
        self.callback = callback
        self.running = False

    # Capture/sniff a single network packet and extract metadata
    def sniff_packet(self):
        try:
            # Import sniff and layer utilities from Scapy
            from scapy.all import sniff, IP, TCP, UDP
            # Capture one packet with a 1.0 second timeout
            pkts = sniff(count=1, timeout=1.0)
            if not pkts:
                return None
            
            pkt = pkts[0]
            curr_time = time.time()

            # Extract details if the IP layer is present
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                # Identify the protocol: TCP, UDP, or generic IP
                protocol = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "IP")
                # Parse source and destination ports
                sport = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (int(pkt[UDP].sport) if pkt.haslayer(UDP) else 0)
                dport = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (int(pkt[UDP].dport) if pkt.haslayer(UDP) else 0)
                # Check TCP flags if the TCP layer is present
                tcp_flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else ""
                
                # Return sniffed packet details for the dashboard feed
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
            # Log error without crashing to provide fallback control
            logger.debug(f"Packet sniffing issue: {err}")
            return None
        return None
