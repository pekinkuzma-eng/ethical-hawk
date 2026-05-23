from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from core.detector import Detector
from config import INTERFACE

detector = Detector()


class Sniffer:

    def process_packet(self, packet):
        try:
            if not packet.haslayer(IP):
                return
                
            source_ip = packet[IP].src
            
            # Ищем HTTP трафик на порту 9999
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                if tcp.dport == 9999 or tcp.sport == 9999:
                    print(f"[HTTP] Port 9999 traffic from {source_ip}")
            
            payload = ""
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                
                # Показываем только HTTP подобный трафик
                if "GET" in payload or "POST" in payload or "HTTP" in payload:
                    print(f"[RAW] {source_ip}: {payload[:200]}")
                    
                    if detector.detect_sql_injection(payload):
                        print(f"[!!!] SQL INJECTION from {source_ip}!")
                        detector.process_attack(source_ip, payload, "SQL Injection")
                    elif detector.detect_xss(payload):
                        print(f"[!!!] XSS from {source_ip}!")
                        detector.process_attack(source_ip, payload, "XSS Attack")
                    elif detector.detect_bruteforce(source_ip):
                        print(f"[!!!] BRUTE FORCE from {source_ip}!")
                        detector.process_attack(source_ip, payload, "Brute Force")

        except Exception as error:
            print(f"[ERROR] {error}")

    def start(self):
        print(f"[INFO] Traffic monitoring started on {INTERFACE}...")
        sniff(iface=INTERFACE, prn=self.process_packet, store=False)
