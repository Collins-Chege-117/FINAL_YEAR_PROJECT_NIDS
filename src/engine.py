import scapy.all as scapy
from scapy.layers.inet import IP
import requests
import os
import tkinter as tk
from tkinter import simpledialog
from dotenv import load_dotenv
from threat_intel import ThreatIntel # Import your class

load_dotenv()

class NIDSSniffer:
    def __init__(self):
        self.RAILWAY_API_URL = "https://web-production-8c5fe.up.railway.app/api/alerts"
        root = tk.Tk()
        root.withdraw() 
        self.username = simpledialog.askstring("NIDS Shield", "Enter your Username:")
        root.destroy()
        self.intel = ThreatIntel() # Initialize Intel Class
        self.checked_ips = {} # Local cache to save API credits

    def report_alert(self, ip, threat_type):
        payload = {
            "username": self.username,
            "source_ip": ip,
            "threat_type": threat_type,
            "severity": "HIGH"
        }
        try:
            requests.post(self.RAILWAY_API_URL, json=payload, timeout=15)
            print(f"[ALERT SENT] {ip} | {threat_type}")
        except Exception as e:
            print(f"[API ERROR] {e}")

    def sniff_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst # Capture the destination!

            # Logic: If the destination is NOT your local IP, it's the threat
            target_ip = None
            if not dst_ip.startswith(("192.168.", "127.", "10.")):
                target_ip = dst_ip
            # Logic: If the source is NOT your local IP, it's a threat attacking you
            elif not src_ip.startswith(("192.168.", "127.", "10.")):
                target_ip = src_ip

            if not target_ip or target_ip in self.checked_ips:
                return

            # NEW: Check both reputation signals for the 'target_ip'
            report = self.intel.get_threat_report(target_ip)
            if report:
                self.report_alert(target_ip, report)
            else:
                self.report_alert(target_ip, "[SAFE]")
                
            self.checked_ips[target_ip] = True



    def start(self):
        print("🛡️ NIDS Engine Started. Monitoring Live Traffic...")
        scapy.sniff(prn=self.sniff_callback, store=False)

if __name__ == "__main__":
    scanner = NIDSSniffer()
    scanner.start()
