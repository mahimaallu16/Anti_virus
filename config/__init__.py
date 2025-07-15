"""
Configuration management for antivirus system.

This module provides centralized configuration management including
settings, constants, and environment-specific configurations.
"""

from .settings import get_settings, Settings
from .constants import *

__all__ = [
    'get_settings',
    'Settings',
    'QUARANTINE_DIR',
    'UPLOAD_DIR',
    'CACHE_DIR',
    'SIGNATURE_DIR',
    'LOG_DIR',
    'DEFAULT_THREAT_THRESHOLD',
    'DEFAULT_SCAN_INTERVAL',
    'DEFAULT_MAX_WORKERS'
] 