import requests
import os
from dotenv import load_dotenv

load_dotenv()


class ThreatIntel:
    def __init__(self):
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.otx_key = os.getenv("OTX_API_KEY")

    def check_abuseipdb(self, ip):
        if not self.abuse_key:
            return 0

        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Accept": "application/json",
            "Key": self.abuse_key
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            data = response.json()
            return data.get("data", {}).get("abuseConfidenceScore", 0)
        except:
            return 0

    def check_alienvault(self, ip):
        if not self.otx_key:
            return False

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}

        try:
            response = requests.get(url, headers=headers, timeout=5)
            data = response.json()
            return data.get("pulse_info", {}).get("count", 0) > 0
        except:
            return False

    def get_threat_report(self, ip):
        if ip.startswith(("192.168.", "127.", "10.", "172.16.")):
            return None

        abuse_score = self.check_abuseipdb(ip)
        is_otx = self.check_alienvault(ip)

        if abuse_score > 50 or is_otx:
            report = f"Malicious IP | Abuse Score: {abuse_score}"
            if is_otx:
                report += " | Found in OTX"
            return report

        return None