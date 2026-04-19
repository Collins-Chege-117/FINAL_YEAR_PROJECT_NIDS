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

    def check_threat_intel(self, ip):
        """Check IP against AbuseIPDB and AlienVault"""
        
        # 🔹 AbuseIPDB
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Key": self.ABUSE_KEY
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            res = requests.get(url, headers=headers, params=params, timeout=5)
            data = res.json()

            score = data.get("data", {}).get("abuseConfidenceScore", 0)

            if score > 50:
                return f"AbuseIPDB Flagged (Score: {score})"

        except Exception as e:
            print(f"[AbuseIPDB ERROR] {e}")

        # 🔹 AlienVault OTX
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.OTX_KEY}

            res = requests.get(url, headers=headers, timeout=5)
            data = res.json()

            if data.get("pulse_info", {}).get("count", 0) > 0:
                return "AlienVault OTX Malicious IP"

        except Exception as e:
            print(f"[OTX ERROR] {e}")

        return None

    def report_alert(self, ip, threat_type):
        """Send alert to backend"""
        payload = {
            "user_id": self.USER_ID,
            "source_ip": ip,
            "threat_type": threat_type,
            "severity": "HIGH"
        }

        try:
            response = requests.post(self.RAILWAY_API_URL, json=payload, timeout=5)
            print(f"[ALERT SENT] {ip} | {threat_type}")
            print(f"[DEBUG] Status: {response.status_code}, Response: {response.text}")

        except Exception as e:
            print(f"[NETWORK ERROR] Could not reach backend: {e}")

    def sniff_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            print(f"[PACKET] {src_ip}")

            # Ignore local traffic
            if src_ip.startswith(("192.168.", "127.", "10.")):
                return

            # 🔹 TEMP TEST TRIGGER (REMOVE LATER)
            if src_ip == "8.8.8.8":
                self.report_alert(src_ip, "Test Alert")
                return

            # 🔹 Basic SQLi detection
            if packet.haslayer(scapy.Raw):
                payload = str(packet[scapy.Raw].load).lower()

                if any(sqli in payload for sqli in ["select", "union", "drop", "insert"]):
                    self.report_alert(src_ip, "SQL Injection Attempt")
                    return

            # 🔹 Threat intel
            threat = self.check_threat_intel(src_ip)
            if threat:
                self.report_alert(src_ip, threat)

    def start(self):
        print("🛡️ NIDS Engine Active...")
        scapy.sniff(prn=self.sniff_callback, store=False)


if __name__ == "__main__":
    scanner = NIDSSniffer()
    scanner.start()
