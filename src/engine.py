import scapy.all as scapy
from scapy.layers.inet import IP
import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

class NIDSSniffer:
    def __init__(self):

        self.RAILWAY_API_URL = "https://railway.app"
        self.USER_ID = 1 
        
        self.ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
        self.OTX_KEY = os.getenv("OTX_API_KEY")

    def check_threat_intel(self, ip):
        
        try:
            url = "https://abuseipdb.com"
            headers = {"Accept": "application/json", "Key": self.ABUSE_KEY}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            res = requests.get(url, headers=headers, params=params, timeout=3)
            score = res.json().get("data", {}).get("abuseConfidenceScore", 0)
            if score > 50: return f"AbuseIPDB Flagged (Score: {score})"
        except: pass

        try:
            url = f"https://alienvault.com{ip}/general"
            headers = {"X-OTX-API-KEY": self.OTX_KEY}
            res = requests.get(url, headers=headers, timeout=3)
            if res.json().get("pulse_info", {}).get("count", 0) > 0:
                return "AlienVault OTX Malicious IP"
        except: pass

        return None

    def report_alert(self, ip, threat_type):
        """Sends the detection to the Railway Dashboard"""
        payload = {
            "user_id": self.USER_ID,
            "source_ip": ip,
            "threat_type": threat_type,
            "severity": "HIGH"
        }
        try:
            requests.post(self.RAILWAY_API_URL, json=payload, timeout=5)
            print(f"[ALERT SENT] {ip} | {threat_type}")
        except Exception as e:
            print(f"[NETWORK ERROR] Could not reach Dashboard: {e}")

    def sniff_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            
            if src_ip.startswith(("192.168.", "127.", "10.")):
                return

            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load).lower()
                if any(sqli in payload for sqli in ["select", "union", "drop", "insert"]):
                    self.report_alert(src_ip, "SQL Injection Attempt")
                    return

            threat = self.check_threat_intel(src_ip)
            if threat:
                self.report_alert(src_ip, threat)

    def start(self):
        print(f"🛡️ NIDS Engine Active. Monitoring network...")
        scapy.sniff(prn=self.sniff_callback, store=False)

if __name__ == "__main__":
    scanner = NIDSSniffer()
    scanner.start()
