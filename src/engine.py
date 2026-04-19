import scapy.all as scapy
from scapy.layers.inet import IP
import requests
import os
from dotenv import load_dotenv
from threat_intel import ThreatIntel # Import your class

load_dotenv()

class NIDSSniffer:
    def __init__(self):
        self.RAILWAY_API_URL = "https://railway.app"
        self.USER_ID = 1
        self.intel = ThreatIntel() # Initialize Intel Class
        self.checked_ips = {} # Local cache to save API credits

    def report_alert(self, ip, threat_type):
        payload = {
            "user_id": self.USER_ID,
            "source_ip": ip,
            "threat_type": threat_type,
            "severity": "HIGH"
        }
        try:
            requests.post(self.RAILWAY_API_URL, json=payload, timeout=5)
            print(f"🚨 [ALERT SENT] {ip} | {threat_type}")
        except Exception as e:
            print(f"❌ [API ERROR] {e}")

    def sniff_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # 1. Skip local traffic and previously checked safe IPs
            if src_ip.startswith(("192.168.", "127.", "10.", "172.16.")) or src_ip in self.checked_ips:
                return

            # 2. Check for SQL Injection in Raw Data
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load).lower()
                if any(p in payload for p in ["select", "union", "1=1", "--"]):
                    self.report_alert(src_ip, "SQL Injection Pattern Detected")
                    self.checked_ips[src_ip] = True
                    return

            # 3. Use ThreatIntel Class for API Lookups
            threat_report = self.intel.get_threat_report(src_ip)
            if threat_report:
                self.report_alert(src_ip, threat_report)
            
            # Mark as checked so we don't spam APIs for the same IP
            self.checked_ips[src_ip] = True

    def start(self):
        print("🛡️ NIDS Engine Started. Monitoring Live Traffic...")
        scapy.sniff(prn=self.sniff_callback, store=False)

if __name__ == "__main__":
    scanner = NIDSSniffer()
    scanner.start()
