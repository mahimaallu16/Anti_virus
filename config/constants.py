"""
Constants for antivirus system.

This module defines all constants used throughout the antivirus system
including directories, thresholds, and default values.
"""

import os
from pathlib import Path

# Directory constants
BASE_DIR = Path(__file__).parent.parent
QUARANTINE_DIR = BASE_DIR / "quarantine"
UPLOAD_DIR = BASE_DIR / "uploads"
CACHE_DIR = BASE_DIR / "cache"
SIGNATURE_DIR = BASE_DIR / "signatures"
LOG_DIR = BASE_DIR / "logs"
TEMP_DIR = BASE_DIR / "temp"

# Database constants
DATABASE_URL = "sqlite:///./antivirus.db"
QUARANTINE_DB = "quarantine_db.json"

# Scanning constants
DEFAULT_THREAT_THRESHOLD = 50
DEFAULT_SCAN_INTERVAL = 3600  # seconds
DEFAULT_MAX_WORKERS = 4
DEFAULT_QUARANTINE_THRESHOLD = 80
DEFAULT_ALERT_THRESHOLD = 60

# File size limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_QUARANTINE_SIZE = 1024 * 1024 * 100  # 100MB
MAX_ARCHIVE_SIZE = 50 * 1024 * 1024  # 50MB

# Retention settings
QUARANTINE_RETENTION_DAYS = 30
LOG_RETENTION_DAYS = 90
CACHE_RETENTION_DAYS = 7

# Security constants
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# API constants
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'
VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY')

# Alert severity levels
class AlertSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Risk levels
class RiskLevel:
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Scan types
class ScanType:
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    SYSTEM = "system"
    REAL_TIME = "real_time"

# File extensions
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', 
    '.ps1', '.js', '.jar', '.msi', '.com', '.pif',
    '.reg', '.inf', '.hta', '.wsf', '.wsh'
}

ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.xz', '.cab', '.iso', '.dmg'
}

# Whitelist settings
WHITELISTED_PATHS = {
    'C:\\Windows\\System32\\',
    'C:\\Windows\\SysWOW64\\',
    'C:\\Program Files\\',
    'C:\\Program Files (x86)\\',
    'C:\\Users\\AppData\\Local\\Microsoft\\',
    'C:\\Users\\AppData\\Roaming\\Microsoft\\',
}

WHITELISTED_EXTENSIONS = {
    '.txt', '.log', '.ini', '.cfg', '.xml', '.json', '.csv',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
}

# YARA rule paths
YARA_RULES_PATHS = [
    "signatures/malware.yar",
    "signatures/enterprise_rules.yar",
    "signatures/advanced_malware_families.yar",
    "signatures/advanced_attack_techniques.yar"
]

# Quarantine configuration
QUARANTINE_CONFIG = {
    "auto_quarantine_threshold": DEFAULT_QUARANTINE_THRESHOLD,
    "alert_threshold": DEFAULT_ALERT_THRESHOLD,
    "max_quarantine_size": MAX_QUARANTINE_SIZE,
    "retention_days": QUARANTINE_RETENTION_DAYS,
    "enable_notifications": True,
    "backup_before_delete": True,
}

# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
    },
    "handlers": {
        "default": {
            "level": "INFO",
            "formatter": "standard",
            "class": "logging.StreamHandler",
        },
        "file": {
            "level": "INFO",
            "formatter": "standard",
            "class": "logging.FileHandler",
            "filename": LOG_DIR / "antivirus.log",
            "mode": "a",
        },
    },
    "loggers": {
        "": {
            "handlers": ["default", "file"],
            "level": "INFO",
            "propagate": False
        }
    }
} 