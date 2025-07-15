"""
Main detection engine for antivirus system.

This module provides a unified interface for all detection methods
including signature, heuristic, and behavioral analysis.
"""

import logging
from typing import Dict, Optional, List
from pathlib import Path

from .signature_detector import SignatureDetector
from .heuristic_detector import HeuristicDetector
from .behavioral_detector import BehavioralDetector
from ...config.settings import get_settings

logger = logging.getLogger(__name__)

class DetectionEngine:
    """
    Main detection engine that coordinates all detection methods.
    
    This class provides a unified interface for:
    - Signature-based detection
    - Heuristic analysis
    - Behavioral analysis
    - Threat scoring and classification
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.signature_detector = SignatureDetector()
        self.heuristic_detector = HeuristicDetector()
        self.behavioral_detector = BehavioralDetector()
    
    def detect_signatures(self, file_path: str) -> Optional[Dict]:
        """
        Perform signature-based detection on a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary with signature detection results if threat found
        """
        try:
            return self.signature_detector.detect(file_path)
        except Exception as e:
            logger.error(f"Signature detection failed for {file_path}: {e}")
            return None
    
    def heuristic_analysis(self, file_path: str) -> Optional[Dict]:
        """
        Perform heuristic analysis on a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary with heuristic analysis results if suspicious patterns found
        """
        try:
            return self.heuristic_detector.analyze(file_path)
        except Exception as e:
            logger.error(f"Heuristic analysis failed for {file_path}: {e}")
            return None
    
    def behavioral_analysis(self, file_path: str) -> Optional[Dict]:
        """
        Perform behavioral analysis on a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary with behavioral analysis results if suspicious behavior found
        """
        try:
            return self.behavioral_detector.analyze(file_path)
        except Exception as e:
            logger.error(f"Behavioral analysis failed for {file_path}: {e}")
            return None
    
    def comprehensive_scan(self, file_path: str) -> Dict:
        """
        Perform comprehensive scanning using all detection methods.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary with comprehensive scan results
        """
        results = {
            'file_path': file_path,
            'signature_detection': None,
            'heuristic_analysis': None,
            'behavioral_analysis': None,
            'total_score': 0,
            'threats': [],
            'risk_level': 'safe'
        }
        
        # Signature detection
        signature_result = self.detect_signatures(file_path)
        if signature_result:
            results['signature_detection'] = signature_result
            results['threats'].append(signature_result)
            results['total_score'] += signature_result.get('score', 0)
        
        # Heuristic analysis
        heuristic_result = self.heuristic_analysis(file_path)
        if heuristic_result:
            results['heuristic_analysis'] = heuristic_result
            results['threats'].append(heuristic_result)
            results['total_score'] += heuristic_result.get('score', 0)
        
        # Behavioral analysis
        behavioral_result = self.behavioral_analysis(file_path)
        if behavioral_result:
            results['behavioral_analysis'] = behavioral_result
            results['threats'].append(behavioral_result)
            results['total_score'] += behavioral_result.get('score', 0)
        
        # Determine risk level
        results['risk_level'] = self._determine_risk_level(results['total_score'])
        
        return results
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on total threat score."""
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
    
    def update_signatures(self) -> bool:
        """
        Update signature database.
        
        Returns:
            True if update successful, False otherwise
        """
        try:
            return self.signature_detector.update_signatures()
        except Exception as e:
            logger.error(f"Signature update failed: {e}")
            return False
    
    def get_detection_stats(self) -> Dict:
        """
        Get detection engine statistics.
        
        Returns:
            Dictionary with detection statistics
        """
        return {
            'signature_count': self.signature_detector.get_signature_count(),
            'heuristic_rules': self.heuristic_detector.get_rule_count(),
            'behavioral_patterns': self.behavioral_detector.get_pattern_count(),
            'last_update': self.signature_detector.get_last_update()
        } 