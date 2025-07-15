import os
import json
import time
import yara
import requests
import logging
from functools import lru_cache
import hashlib
from .config import SIGNATURE_TYPES, config

class SignatureDatabase:
    def __init__(self):
        self.signatures = {
            'hash': {},
            'pattern': {},
            'behavior': {}
        }
        self.yara_rules = None
        self.last_update = 0
        self.update_interval = 86400  # 24 hours
        self.load_signatures()
    
    def load_signatures(self):
        """Load virus signatures from database"""
        try:
            # Load YARA rules
            yara_dir = SIGNATURE_TYPES['yara']
            if os.path.exists(yara_dir):
                yara_files = [f for f in os.listdir(yara_dir) if f.endswith('.yar')]
                if yara_files:
                    self.yara_rules = yara.compile(filepath=os.path.join(yara_dir, yara_files[0]))
            
            # Load hash signatures
            hash_file = os.path.join(SIGNATURE_TYPES['hash'], "hash_signatures.json")
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    self.signatures['hash'] = json.load(f)
            
            # Load pattern signatures
            pattern_file = os.path.join(SIGNATURE_TYPES['pattern'], "pattern_signatures.json")
            if os.path.exists(pattern_file):
                with open(pattern_file, 'r') as f:
                    self.signatures['pattern'] = json.load(f)
            
            # Load behavior signatures
            behavior_file = os.path.join(SIGNATURE_TYPES['behavior'], "behavior_signatures.json")
            if os.path.exists(behavior_file):
                with open(behavior_file, 'r') as f:
                    self.signatures['behavior'] = json.load(f)
                    
        except Exception as e:
            logging.error(f"Error loading signatures: {str(e)}")
    
    def update_signatures(self):
        """Update virus signatures from online database"""
        current_time = time.time()
        if current_time - self.last_update < self.update_interval:
            return
        
        try:
            # Update YARA rules
            yara_urls = [
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/index.yar",
                "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/index.yar"
            ]
            yara_dir = SIGNATURE_TYPES['yara']
            for i, url in enumerate(yara_urls):
                response = requests.get(url)
                if response.status_code == 200:
                    with open(os.path.join(yara_dir, f"signatures_{i}.yar"), 'w') as f:
                        f.write(response.text)
            
            # Update hash signatures
            hash_urls = [
                "https://raw.githubusercontent.com/malwares/HashDatabase/master/hashes.json",
                "https://raw.githubusercontent.com/malwares/HashDatabase/master/known_malware.json"
            ]
            hash_dir = SIGNATURE_TYPES['hash']
            for i, url in enumerate(hash_urls):
                response = requests.get(url)
                if response.status_code == 200:
                    with open(os.path.join(hash_dir, f"hash_signatures_{i}.json"), 'w') as f:
                        f.write(response.text)
            
            # Update pattern signatures
            pattern_url = "https://raw.githubusercontent.com/malwares/PatternDatabase/master/patterns.json"
            response = requests.get(pattern_url)
            if response.status_code == 200:
                with open(os.path.join(SIGNATURE_TYPES['pattern'], "pattern_signatures.json"), 'w') as f:
                    f.write(response.text)
            
            # Update behavior signatures
            behavior_url = "https://raw.githubusercontent.com/malwares/BehaviorDatabase/master/behaviors.json"
            response = requests.get(behavior_url)
            if response.status_code == 200:
                with open(os.path.join(SIGNATURE_TYPES['behavior'], "behavior_signatures.json"), 'w') as f:
                    f.write(response.text)
            
            self.last_update = current_time
            self.load_signatures()  # Reload all signatures
            logging.info("Virus signatures updated successfully")
        except Exception as e:
            logging.error(f"Error updating signatures: {str(e)}")

@lru_cache(maxsize=1000)
def get_file_hash(file_path):
    """Calculate file hash with caching"""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None 