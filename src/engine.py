import scapy.all as scapy
from scapy.layers.inet import IP
import requests
import os
from dotenv import load_dotenv

load_dotenv()

class NIDSSniffer:
    def __init__(self):
        self.RAILWAY_API_URL = "https://web-production-8c5fe.up.railway.app/api/alerts"
        self.USER_ID = 1
        self.ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
        self.OTX_KEY = os.getenv("OTX_API_KEY")
        
        # 🔹 CACHE: Prevents checking the same IP repeatedly
        self.checked_ips = {} 

    def check_threat_intel(self, ip):
        if ip in self.checked_ips:
            return None # Already checked this session
        
        # 🔹 AbuseIPDB Check
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": self.ABUSE_KEY}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            res = requests.get(url, headers=headers, params=params, timeout=3)
            score = res.json().get("data", {}).get("abuseConfidenceScore", 0)
            
            if score > 50:
                self.checked_ips[ip] = True
                return f"AbuseIPDB Malicious (Score: {score})"
        except: pass

        # 🔹 OTX Check
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.OTX_KEY}
            res = requests.get(url, headers=headers, timeout=3)
            if res.json().get("pulse_info", {}).get("count", 0) > 0:
                self.checked_ips[ip] = True
                return "AlienVault OTX Threat Match"
        except: pass

        self.checked_ips[ip] = True # Mark as safe so we don't check again
        return None

    def report_alert(self, ip, threat_type):
        payload = {
            "user_id": self.USER_ID,
            "source_ip": ip,
            "threat_type": threat_type,
            "severity": "HIGH"
        }
        try:
            requests.post(self.RAILWAY_API_URL, json=payload, timeout=5)
            print(f"🚨 ALERT SENT: {ip} | {threat_type}")
        except Exception as e:
            print(f"❌ API Error: {e}")

    def sniff_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            # Ignore local traffic to save API credits
            if src_ip.startswith(("192.168.", "127.", "10.", "172.")):
                return

            # 🔹 DEMO TRICK: Manual trigger
            if "8.8.8.8" in src_ip:
                self.report_alert(src_ip, "Simulated DNS Hijack")

            # 🔹 SQLi Detection (Demo by typing 'OR 1=1' in any login field)
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load).lower()
                sqli_patterns = ["select", "union", "drop", "1=1", "--"]
                if any(p in payload for p in sqli_patterns):
                    self.report_alert(src_ip, "SQL Injection Pattern Detected")

            # 🔹 Intelligence Lookup
            threat = self.check_threat_intel(src_ip)
            if threat:
                self.report_alert(src_ip, threat)

    def start(self):
        print("🛡️ NIDS Engine Active... Sniffing Live Traffic.")
        # store=False saves memory
        scapy.sniff(prn=self.sniff_callback, store=False)

if __name__ == "__main__":
    scanner = NIDSSniffer()
    scanner.start()
