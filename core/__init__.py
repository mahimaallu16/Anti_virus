"""
Core antivirus functionality module.

This module contains the core scanning, detection, quarantine, and monitoring
capabilities of the antivirus system.
"""

from .scanner import FileScanner, ProcessScanner
from .detection import DetectionEngine, SignatureDetector, HeuristicDetector
from .quarantine import QuarantineManager
from .monitoring import RealTimeMonitor

__all__ = [
    'FileScanner',
    'ProcessScanner', 
    'DetectionEngine',
    'SignatureDetector',
    'HeuristicDetector',
    'QuarantineManager',
    'RealTimeMonitor'
] 