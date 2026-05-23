from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Raw

from core.detector import Detector


detector = Detector()


class Sniffer:

    def process_packet(self, packet):

        try:

            if packet.haslayer(IP):
                source_ip = packet[IP].src

                payload = ""

                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode(errors="ignore")

                if detector.detect_sql_injection(payload):
                    detector.process_attack(
                        source_ip,
                        payload,
                        "SQL Injection"
                    )

                elif detector.detect_xss(payload):
                    detector.process_attack(
                        source_ip,
                        payload,
                        "XSS Attack"
                    )

                elif detector.detect_bruteforce(source_ip):
                    detector.process_attack(
                        source_ip,
                        payload,
                        "Brute Force"
                    )

        except Exception as error:
            print(f"Packet processing error: {error}")

    def start(self):

        print("[INFO] Traffic monitoring started...")

        sniff(
            prn=self.process_packet,
            store=False
        )
