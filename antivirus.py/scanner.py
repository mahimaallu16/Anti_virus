import os
import psutil
import subprocess
import json
import logging
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import queue
from .config import MAX_WORKERS, config
from .signatures import SignatureDatabase, get_file_hash

class FileScanner:
    def __init__(self):
        self.suspicious_extensions = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs'}
        self.known_hashes = set()
        self.signature_db = SignatureDatabase()
        self.load_known_hashes()
    
    def load_known_hashes(self):
        """Load known safe file hashes from cache"""
        cache_file = os.path.join(os.path.expanduser("~"), "AntivirusCache", "known_hashes.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    self.known_hashes = set(json.load(f))
            except:
                self.known_hashes = set()
    
    def save_known_hashes(self):
        """Save known safe file hashes to cache"""
        cache_file = os.path.join(os.path.expanduser("~"), "AntivirusCache", "known_hashes.json")
        with open(cache_file, 'w') as f:
            json.dump(list(self.known_hashes), f)
    
    def scan_file(self, file_path):
        """Scan a single file with signature detection"""
        try:
            if not os.path.exists(file_path):
                return None
            
            # Check extension first (fast)
            if not any(file_path.lower().endswith(ext) for ext in self.suspicious_extensions):
                return None
            
            # Check hash against known safe files
            file_hash = get_file_hash(file_path)
            if file_hash in self.known_hashes:
                return None
            
            # Check against virus signatures
            signature_result = self.signature_db.check_file_signature(file_path)
            if signature_result:
                return {
                    'path': file_path,
                    'threat': f"Virus Signature Match: {signature_result['threat']}",
                    'score': signature_result['score']
                }
            
            # Analyze file behavior
            behavior = self.analyze_file_behavior(file_path)
            if behavior.get('score', 0) > 0:
                return {
                    'path': file_path,
                    'threat': "Suspicious Behavior",
                    'score': behavior['score']
                }
            else:
                # Add to known safe hashes
                self.known_hashes.add(file_hash)
                self.save_known_hashes()
            return None
        except Exception as e:
            logging.error(f"Error scanning {file_path}: {str(e)}")
            return None
    
    def analyze_file_behavior(self, file_path):
        """Analyze file behavior efficiently"""
        try:
            if file_path.endswith('.exe'):
                result = subprocess.run([file_path], capture_output=True, timeout=3, shell=True)
                writes = len(result.stdout.splitlines()) if result.stdout else 0
                return {
                    'writes': writes,
                    'network': bool(result.stderr),
                    'score': 30 if writes > 3 or result.stderr else 0
                }
            return {'writes': 0, 'network': False, 'score': 0}
        except:
            return {'writes': 0, 'network': False, 'score': 0}

class ProcessMonitor:
    def __init__(self):
        self.process_cache = {}
        self.last_scan = 0
        self.scan_interval = 5  # seconds
    
    def get_process_info(self, pid):
        """Get process info with caching"""
        current_time = time.time()
        if pid in self.process_cache and current_time - self.process_cache[pid]['timestamp'] < self.scan_interval:
            return self.process_cache[pid]['info']
        
        try:
            proc = psutil.Process(pid)
            info = {
                'pid': pid,
                'name': proc.name(),
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'memory_percent': proc.memory_percent(),
                'exe': proc.exe() if hasattr(proc, 'exe') else None,
                'connections': proc.connections() if hasattr(proc, 'connections') else [],
                'timestamp': current_time
            }
            self.process_cache[pid] = {'info': info, 'timestamp': current_time}
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def scan_processes(self):
        """Efficiently scan running processes"""
        suspicious = []
        current_time = time.time()
        
        # Clean old cache entries
        self.process_cache = {
            pid: data for pid, data in self.process_cache.items()
            if current_time - data['timestamp'] < self.scan_interval
        }
        
        for proc in psutil.process_iter(['pid']):
            try:
                proc_info = self.get_process_info(proc.info['pid'])
                if proc_info:
                    score = self.calculate_threat_score(proc_info)
                    if score > config["threat_threshold"]:
                        suspicious.append({'info': proc_info, 'score': score})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspicious
    
    def calculate_threat_score(self, proc_info):
        """Calculate threat score efficiently"""
        score = 0
        try:
            if proc_info['cpu_percent'] > 75: score += 25
            if proc_info['memory_percent'] > 70: score += 25
            if len(proc_info['connections']) > 10: score += 30
            if any(susp in proc_info['name'].lower() for susp in ['hack', 'crack', 'keylog', 'spy', 'malware']): score += 40
            return min(score, 100)
        except:
            return score

def scan_directory(directory, progress_callback=None):
    """Scan directory efficiently using thread pool"""
    scanner = FileScanner()
    suspicious_files = []
    file_queue = queue.Queue()
    result_queue = queue.Queue()
    
    def worker():
        while True:
            try:
                file_path = file_queue.get_nowait()
                result = scanner.scan_file(file_path)
                if result:
                    result_queue.put(result)
                if progress_callback:
                    progress_callback(1)
            except queue.Empty:
                break
    
    # Collect all files first
    total_files = 0
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_queue.put(file_path)
            total_files += 1
    
    # Process files in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(worker) for _ in range(MAX_WORKERS)]
        processed = 0
        while processed < total_files:
            try:
                result = result_queue.get(timeout=1)
                suspicious_files.append(result)
            except queue.Empty:
                pass
            processed += 1
    
    return suspicious_files 