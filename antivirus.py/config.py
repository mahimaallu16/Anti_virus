import os
import json
import logging
from datetime import datetime

# Application Constants
APP_VERSION = "1.0.0"
MAX_WORKERS = min(32, (os.cpu_count() or 1) + 4)

# Directory Paths
QUARANTINE_DIR = os.path.join(os.path.expanduser("~"), "AntivirusQuarantine")
CONFIG_FILE = os.path.join(os.path.expanduser("~"), "antivirus_config.json")
CACHE_DIR = os.path.join(os.path.expanduser("~"), "AntivirusCache")
SIGNATURE_DIR = os.path.join(os.path.expanduser("~"), "AntivirusSignatures")
SIGNATURE_TYPES = {
    'yara': os.path.join(SIGNATURE_DIR, "yara"),
    'hash': os.path.join(SIGNATURE_DIR, "hash"),
    'pattern': os.path.join(SIGNATURE_DIR, "pattern"),
    'behavior': os.path.join(SIGNATURE_DIR, "behavior")
}

# Create necessary directories
for directory in [QUARANTINE_DIR, CACHE_DIR, SIGNATURE_DIR] + list(SIGNATURE_TYPES.values()):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Setup logging
logging.basicConfig(
    filename=os.path.join(os.path.expanduser("~"), "antivirus.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def load_config():
    """Load or create default configuration"""
    default_config = {
        "auto_update": True,
        "scan_interval": 3600,
        "threat_threshold": 50
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning("Config file corrupted, using defaults")
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(default_config, f)
    return default_config

# Load configuration
config = load_config() 