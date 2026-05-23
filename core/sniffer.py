from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Raw

from core.detector import Detector
from config import INTERFACE


detector = Detector()


class Sniffer:

    def process_packet(self, packet):

        try:

            if packet.haslayer(IP):

                source_ip = packet[IP].src

                # Фильтрация multicast/broadcast
                if (
                    source_ip.startswith("239.")
                    or source_ip.startswith("224.")
                ):
                    return

                payload = ""

                if packet.haslayer(Raw):

                    payload = packet[Raw].load.decode(
                        errors="ignore"
                    )

                    # Игнорируем SSDP/UPnP шум
                    if "NOTIFY" in payload:
                        return

                print(
                    f"[PACKET] "
                    f"{source_ip} -> {payload[:100]}"
                )

                # SQL Injection detection
                if detector.detect_sql_injection(payload):

                    detector.process_attack(
                        source_ip,
                        payload,
                        "SQL Injection"
                    )

                # XSS detection
                elif detector.detect_xss(payload):

                    detector.process_attack(
                        source_ip,
                        payload,
                        "XSS Attack"
                    )

                # Brute-force detection
                elif detector.detect_bruteforce(source_ip):

                    detector.process_attack(
                        source_ip,
                        payload,
                        "Brute Force"
                    )

        except Exception as error:

            print(
                f"[SNIFFER ERROR] {error}"
            )

    def start(self):

        print(
            "[INFO] Traffic monitoring started..."
        )

        sniff(
            iface=INTERFACE,
            prn=self.process_packet,
            store=False
        )
