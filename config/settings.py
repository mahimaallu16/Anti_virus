"""
Settings management for antivirus system.

This module provides centralized settings management using Pydantic
for type safety and validation.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from pydantic import BaseSettings, Field, validator
from functools import lru_cache

from .constants import (
    BASE_DIR, QUARANTINE_DIR, UPLOAD_DIR, CACHE_DIR, SIGNATURE_DIR,
    LOG_DIR, TEMP_DIR, DEFAULT_THREAT_THRESHOLD, DEFAULT_SCAN_INTERVAL,
    DEFAULT_MAX_WORKERS, DEFAULT_QUARANTINE_THRESHOLD, DEFAULT_ALERT_THRESHOLD,
    MAX_FILE_SIZE, MAX_QUARANTINE_SIZE, MAX_ARCHIVE_SIZE,
    QUARANTINE_RETENTION_DAYS, LOG_RETENTION_DAYS, CACHE_RETENTION_DAYS,
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
    VIRUSTOTAL_URL, SUSPICIOUS_EXTENSIONS, ARCHIVE_EXTENSIONS,
    WHITELISTED_PATHS, WHITELISTED_EXTENSIONS, YARA_RULES_PATHS
)

class Settings(BaseSettings):
    """Application settings with validation and defaults."""
    
    # Directory settings
    base_dir: Path = Field(default=BASE_DIR, description="Base application directory")
    quarantine_dir: Path = Field(default=QUARANTINE_DIR, description="Quarantine directory")
    upload_dir: Path = Field(default=UPLOAD_DIR, description="Upload directory")
    cache_dir: Path = Field(default=CACHE_DIR, description="Cache directory")
    signature_dir: Path = Field(default=SIGNATURE_DIR, description="Signature directory")
    log_dir: Path = Field(default=LOG_DIR, description="Log directory")
    temp_dir: Path = Field(default=TEMP_DIR, description="Temporary directory")
    
    # Database settings
    database_url: str = Field(default="sqlite:///./antivirus.db", description="Database URL")
    quarantine_db: str = Field(default="quarantine_db.json", description="Quarantine database file")
    
    # Scanning settings
    threat_threshold: int = Field(default=DEFAULT_THREAT_THRESHOLD, ge=0, le=100, description="Threat detection threshold")
    scan_interval: int = Field(default=DEFAULT_SCAN_INTERVAL, ge=60, description="Scan interval in seconds")
    max_workers: int = Field(default=DEFAULT_MAX_WORKERS, ge=1, le=16, description="Maximum worker threads")
    quarantine_threshold: int = Field(default=DEFAULT_QUARANTINE_THRESHOLD, ge=0, le=100, description="Auto-quarantine threshold")
    alert_threshold: int = Field(default=DEFAULT_ALERT_THRESHOLD, ge=0, le=100, description="Alert threshold")
    
    # File size limits
    max_file_size: int = Field(default=MAX_FILE_SIZE, ge=1024*1024, description="Maximum file size in bytes")
    max_quarantine_size: int = Field(default=MAX_QUARANTINE_SIZE, ge=1024*1024, description="Maximum quarantine size in bytes")
    max_archive_size: int = Field(default=MAX_ARCHIVE_SIZE, ge=1024*1024, description="Maximum archive size in bytes")
    
    # Retention settings
    quarantine_retention_days: int = Field(default=QUARANTINE_RETENTION_DAYS, ge=1, description="Quarantine retention days")
    log_retention_days: int = Field(default=LOG_RETENTION_DAYS, ge=1, description="Log retention days")
    cache_retention_days: int = Field(default=CACHE_RETENTION_DAYS, ge=1, description="Cache retention days")
    
    # Security settings
    secret_key: str = Field(default=SECRET_KEY, description="Secret key for JWT tokens")
    algorithm: str = Field(default=ALGORITHM, description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=ACCESS_TOKEN_EXPIRE_MINUTES, ge=1, description="Access token expiry minutes")
    
    # API settings
    virustotal_url: str = Field(default=VIRUSTOTAL_URL, description="VirusTotal API URL")
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key")
    
    # File extensions
    suspicious_extensions: Set[str] = Field(default=SUSPICIOUS_EXTENSIONS, description="Suspicious file extensions")
    archive_extensions: Set[str] = Field(default=ARCHIVE_EXTENSIONS, description="Archive file extensions")
    
    # Whitelist settings
    whitelisted_paths: Set[str] = Field(default=WHITELISTED_PATHS, description="Whitelisted paths")
    whitelisted_extensions: Set[str] = Field(default=WHITELISTED_EXTENSIONS, description="Whitelisted file extensions")
    
    # YARA settings
    yara_rules_paths: List[str] = Field(default=YARA_RULES_PATHS, description="YARA rule file paths")
    
    # Feature flags
    enable_real_time_protection: bool = Field(default=True, description="Enable real-time protection")
    enable_web_protection: bool = Field(default=True, description="Enable web protection")
    enable_email_protection: bool = Field(default=True, description="Enable email protection")
    enable_file_system_protection: bool = Field(default=True, description="Enable file system protection")
    enable_network_protection: bool = Field(default=True, description="Enable network protection")
    enable_auto_quarantine: bool = Field(default=True, description="Enable auto-quarantine")
    enable_notifications: bool = Field(default=True, description="Enable notifications")
    backup_before_delete: bool = Field(default=True, description="Backup files before deletion")
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    enable_file_logging: bool = Field(default=True, description="Enable file logging")
    enable_console_logging: bool = Field(default=True, description="Enable console logging")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    @validator('quarantine_dir', 'upload_dir', 'cache_dir', 'signature_dir', 'log_dir', 'temp_dir')
    def create_directories(cls, v):
        """Create directories if they don't exist."""
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    @validator('virustotal_api_key', pre=True)
    def get_virustotal_api_key(cls, v):
        """Get VirusTotal API key from environment if not provided."""
        return v or os.environ.get('VT_API_KEY')
    
    @validator('secret_key', pre=True)
    def get_secret_key(cls, v):
        """Get secret key from environment if not provided."""
        return v or os.environ.get('SECRET_KEY', SECRET_KEY)
    
    def get_quarantine_config(self) -> Dict:
        """Get quarantine configuration."""
        return {
            "auto_quarantine_threshold": self.quarantine_threshold,
            "alert_threshold": self.alert_threshold,
            "max_quarantine_size": self.max_quarantine_size,
            "retention_days": self.quarantine_retention_days,
            "enable_notifications": self.enable_notifications,
            "backup_before_delete": self.backup_before_delete,
        }
    
    def get_logging_config(self) -> Dict:
        """Get logging configuration."""
        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                },
            },
            "handlers": {
                "default": {
                    "level": self.log_level,
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                } if self.enable_console_logging else {},
                "file": {
                    "level": self.log_level,
                    "formatter": "standard",
                    "class": "logging.FileHandler",
                    "filename": self.log_dir / "antivirus.log",
                    "mode": "a",
                } if self.enable_file_logging else {},
            },
            "loggers": {
                "": {
                    "handlers": [k for k, v in {
                        "default": self.enable_console_logging,
                        "file": self.enable_file_logging
                    }.items() if v],
                    "level": self.log_level,
                    "propagate": False
                }
            }
        }

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings() 