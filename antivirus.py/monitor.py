import os
import time
import logging
import threading
import winreg
import psutil
from .config import config
from .scanner import ProcessMonitor, FileScanner
import queue
from concurrent.futures import ThreadPoolExecutor
import requests
from core.detection.detection_engine import DetectionEngine

# Try to import scapy, but make it optional
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class SystemMonitor:
    def __init__(self):
        self.process_monitor = ProcessMonitor()
        self.file_scanner = FileScanner()
        self.stop_event = threading.Event()
        self.suspicious_ips = ["192.168.1.1", "10.0.0.5"]
        self.analysis_cache = {}  # {file_path: (result, timestamp)}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.threat_intel_cache = set()
        self.threat_intel_update_thread = threading.Thread(target=self.update_threat_intel_periodically, daemon=True)
        self.threat_intel_update_thread.start()
        self.browser_names = ["chrome.exe", "firefox.exe", "msedge.exe"]
        self.download_dirs = [os.path.join(os.path.expanduser("~"), "Downloads")]
        self.detection_engine = DetectionEngine()
    
    def scan_and_alert(self, file_path):
        cache_entry = self.analysis_cache.get(file_path)
        if cache_entry and time.time() - cache_entry[1] < 3600:
            return cache_entry[0]
        try:
            from app import create_alert
            scan_result = self.detection_engine.comprehensive_scan(file_path)
            self.analysis_cache[file_path] = (scan_result, time.time())
            if scan_result['total_score'] >= 40:
                create_alert(
                    'high',
                    "Threat Detected",
                    f"Threat in {file_path}",
                    file_info=scan_result
                )
            return scan_result
        except Exception as e:
            logging.error(f"DetectionEngine scan error: {str(e)}")
            return None

    def monitor_system(self):
        """Continuously monitor system for web threats without unnecessary breaks"""
        while not self.stop_event.is_set():
            try:
                # Monitor browser processes
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if proc.info['name'] and proc.info['name'].lower() in self.browser_names:
                        # Monitor downloads in browser download folders
                        for ddir in self.download_dirs:
                            if os.path.exists(ddir):
                                for fname in os.listdir(ddir):
                                    fpath = os.path.join(ddir, fname)
                                    if os.path.isfile(fpath):
                                        self.executor.submit(self.scan_and_alert, fpath)
                # Monitor network for web threats
                if SCAPY_AVAILABLE:
                    try:
                        packets = scapy.sniff(count=10, timeout=2)
                        for packet in packets:
                            if packet.haslayer(scapy.IP):
                                dst_ip = packet[scapy.IP].dst
                                if dst_ip in self.threat_intel_cache:
                                    self.block_ip(dst_ip)
                                    from app import create_alert
                                    create_alert(
                                        'critical',
                                        "Blocked Malicious Web Connection",
                                        f"Blocked connection to {dst_ip} (known malicious)",
                                        file_info={'ip': dst_ip}
                                    )
                    except Exception as e:
                        logging.error(f"Network monitoring error: {str(e)}")
                time.sleep(0.5)  # Yield briefly to avoid CPU hogging
            except Exception as e:
                logging.error(f"Monitoring error: {str(e)}")
                time.sleep(1)
    
    def monitor_registry(self):
        """Monitor Windows registry for suspicious changes"""
        suspicious_changes = []
        try:
            with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                with winreg.OpenKey(hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(susp in value.lower() for susp in ['hack', 'crack', 'malware', 'rundll']):
                            suspicious_changes.append({'key': name, 'value': value, 'score': 60})
        except WindowsError as e:
            logging.error(f"Registry monitoring error: {str(e)}")
        return suspicious_changes
    
    def monitor_network(self):
        """Monitor network traffic for suspicious activity"""
        suspicious_traffic = []
        if not SCAPY_AVAILABLE:
            return suspicious_traffic
        try:
            packets = scapy.sniff(count=20, timeout=10)
            for packet in packets:
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    if src_ip in self.suspicious_ips or packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in [4444, 6667]:
                        suspicious_traffic.append({'src_ip': src_ip, 'score': 70})
        except Exception as e:
            logging.error(f"Network monitoring error: {str(e)}")
        return suspicious_traffic
    
    def start(self):
        """Start system monitoring"""
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(target=self.monitor_system)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logging.info("Real-time protection started")
    
    def stop(self):
        """Stop system monitoring"""
        self.stop_event.set()
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        logging.info("Real-time protection stopped")

    def block_ip(self, ip):
        # Example: block using Windows Firewall (requires admin)
        try:
            import subprocess
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockMaliciousIP", "dir=out", f"remoteip={ip}", "action=block"], check=True)
        except Exception as e:
            logging.error(f"Failed to block IP {ip}: {str(e)}")

    def update_threat_intel_periodically(self):
        while True:
            try:
                # Example: Fetch from AbuseIPDB (replace with your API key and handle rate limits)
                # abuseipdb_url = 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90'
                # headers = {'Key': 'YOUR_API_KEY', 'Accept': 'application/json'}
                # response = requests.get(abuseipdb_url, headers=headers)
                # if response.status_code == 200:
                #     data = response.json()
                #     self.threat_intel_cache = set(entry['ipAddress'] for entry in data['data'])
                # Example: Fetch from ThreatFox (public feed)
                threatfox_url = 'https://threatfox.abuse.ch/export/json/ip/'
                try:
                    response = requests.get(threatfox_url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        self.threat_intel_cache = set(entry['ioc'] for entry in data.get('data', []) if entry.get('ioc_type') == 'ip')
                except Exception as e:
                    logging.error(f"ThreatFox fetch error: {str(e)}")
                # Add more sources as needed (VirusTotal, custom feeds, etc.)
                logging.info(f"Threat intelligence cache updated: {len(self.threat_intel_cache)} IPs/domains")
            except Exception as e:
                logging.error(f"Threat intelligence update error: {str(e)}")
            time.sleep(3600)  # Refresh every hour 