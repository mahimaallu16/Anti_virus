"""
File scanning functionality for antivirus system.

This module provides comprehensive file scanning capabilities including
signature detection, heuristic analysis, and behavioral analysis.
"""

import os
import hashlib
import yara
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import tempfile
import zipfile
import base64
import re
import subprocess
from datetime import datetime

from ..detection import DetectionEngine
from ...utils.file_utils import get_file_hash, is_archive_file, extract_archive
from ...utils.security_utils import is_digitally_signed, is_whitelisted_file
from ...config.settings import get_settings

logger = logging.getLogger(__name__)

class FileScanner:
    """
    Comprehensive file scanner with multiple detection methods.
    
    This class provides file scanning capabilities including:
    - Signature-based detection using YARA rules
    - Heuristic analysis
    - Behavioral analysis
    - Archive scanning
    - Digital signature verification
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.detection_engine = DetectionEngine()
        self.suspicious_extensions = {
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', 
            '.ps1', '.js', '.jar', '.msi', '.com'
        }
        self.known_hashes = set()
        self.load_known_hashes()
    
    def load_known_hashes(self):
        """Load known safe file hashes from cache."""
        cache_file = self.settings.cache_dir / "known_hashes.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    self.known_hashes = set(json.load(f))
            except Exception as e:
                logger.warning(f"Failed to load known hashes: {e}")
                self.known_hashes = set()
    
    def save_known_hashes(self):
        """Save known safe file hashes to cache."""
        cache_file = self.settings.cache_dir / "known_hashes.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(list(self.known_hashes), f)
        except Exception as e:
            logger.error(f"Failed to save known hashes: {e}")
    
    def scan_file(self, file_path: str) -> Optional[Dict]:
        """
        Scan a single file for threats.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with threat information if threat detected, None otherwise
        """
        try:
            if not os.path.exists(file_path):
                return None
            
            # Quick checks first
            if self._is_quick_safe(file_path):
                return None
            
            # Get file hash
            file_hash = get_file_hash(file_path)
            
            # Check against known safe hashes
            if file_hash in self.known_hashes:
                return None
            
            # Perform comprehensive scan
            scan_result = self._comprehensive_scan(file_path, file_hash)
            
            # If no threat found, add to known safe hashes
            if not scan_result:
                self.known_hashes.add(file_hash)
                self.save_known_hashes()
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            return None
    
    def _is_quick_safe(self, file_path: str) -> bool:
        """Perform quick safety checks."""
        # Check whitelisted files
        if is_whitelisted_file(file_path):
            return True
        
        # Check extension
        file_ext = Path(file_path).suffix.lower()
        if file_ext not in self.suspicious_extensions:
            return True
        
        return False
    
    def _comprehensive_scan(self, file_path: str, file_hash: str) -> Optional[Dict]:
        """Perform comprehensive file scanning."""
        threats = []
        total_score = 0
        
        # Signature detection
        signature_result = self.detection_engine.detect_signatures(file_path)
        if signature_result:
            threats.append(signature_result)
            total_score += signature_result.get('score', 0)
        
        # Heuristic analysis
        heuristic_result = self.detection_engine.heuristic_analysis(file_path)
        if heuristic_result:
            threats.append(heuristic_result)
            total_score += heuristic_result.get('score', 0)
        
        # Behavioral analysis
        behavioral_result = self.detection_engine.behavioral_analysis(file_path)
        if behavioral_result:
            threats.append(behavioral_result)
            total_score += behavioral_result.get('score', 0)
        
        # Archive scanning
        if is_archive_file(file_path):
            archive_result = self._scan_archive(file_path)
            if archive_result:
                threats.extend(archive_result)
                total_score += sum(t.get('score', 0) for t in archive_result)
        
        # Digital signature check
        if not is_digitally_signed(file_path):
            total_score += 10
        
        if threats or total_score > self.settings.threat_threshold:
            return {
                'file_path': file_path,
                'file_hash': file_hash,
                'threats': threats,
                'total_score': total_score,
                'scan_time': datetime.now().isoformat(),
                'risk_level': self._determine_risk_level(total_score)
            }
        
        return None
    
    def _scan_archive(self, file_path: str) -> List[Dict]:
        """Scan archive files for threats."""
        threats = []
        try:
            extracted_files = extract_archive(file_path)
            for extracted_file in extracted_files:
                result = self.scan_file(extracted_file)
                if result:
                    threats.append(result)
                # Clean up extracted file
                try:
                    os.remove(extracted_file)
                except:
                    pass
        except Exception as e:
            logger.error(f"Error scanning archive {file_path}: {e}")
        
        return threats
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on threat score."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "safe"
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """
        Scan a directory for threats.
        
        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            List of threat detection results
        """
        threats = []
        
        if recursive:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    if result:
                        threats.append(result)
        else:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                if os.path.isfile(item_path):
                    result = self.scan_file(item_path)
                    if result:
                        threats.append(result)
        
        return threats 