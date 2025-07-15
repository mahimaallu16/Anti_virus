"""
Scan service for antivirus system.

This service handles scan operations and coordinates between
the API layer and core scanning functionality.
"""

import logging
import asyncio
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json

from ..core.scanner import FileScanner
from ..core.detection import DetectionEngine
from ..config.settings import get_settings, ScanType
from ..utils.file_utils import get_file_hash, format_file_size
from ..models import ScanHistory
from ..database import get_db

logger = logging.getLogger(__name__)

class ScanService:
    """
    Service for handling scan operations.
    
    This service provides methods for:
    - File scanning
    - Directory scanning
    - Scan history management
    - Scan result processing
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.file_scanner = FileScanner()
        self.detection_engine = DetectionEngine()
    
    async def scan_file(self, file_path: str, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Scan a single file for threats.
        
        Args:
            file_path: Path to the file to scan
            user_id: ID of the user performing the scan
            
        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now()
        
        try:
            # Perform the scan
            scan_result = self.file_scanner.scan_file(file_path)
            
            # Record scan history
            if user_id:
                await self._record_scan_history(
                    user_id=user_id,
                    scan_type=ScanType.CUSTOM,
                    scan_path=file_path,
                    threats_found=1 if scan_result else 0,
                    scan_results=scan_result
                )
            
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'file_path': file_path,
                'file_hash': get_file_hash(file_path) if Path(file_path).exists() else None,
                'file_size': format_file_size(Path(file_path).stat().st_size) if Path(file_path).exists() else None,
                'scan_duration': scan_duration,
                'threats_detected': scan_result is not None,
                'scan_result': scan_result,
                'scan_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {
                'success': False,
                'file_path': file_path,
                'error': str(e),
                'scan_time': datetime.now().isoformat()
            }
    
    async def scan_directory(self, directory: str, recursive: bool = True, 
                           user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Scan a directory for threats.
        
        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories
            user_id: ID of the user performing the scan
            
        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now()
        
        try:
            # Perform the scan
            threats = self.file_scanner.scan_directory(directory, recursive)
            
            # Record scan history
            if user_id:
                await self._record_scan_history(
                    user_id=user_id,
                    scan_type=ScanType.CUSTOM,
                    scan_path=directory,
                    threats_found=len(threats),
                    scan_results={'threats': threats}
                )
            
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'directory': directory,
                'recursive': recursive,
                'scan_duration': scan_duration,
                'files_scanned': len(threats),
                'threats_detected': threats,
                'scan_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
            return {
                'success': False,
                'directory': directory,
                'error': str(e),
                'scan_time': datetime.now().isoformat()
            }
    
    async def quick_scan(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Perform a quick scan of common locations.
        
        Args:
            user_id: ID of the user performing the scan
            
        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now()
        
        try:
            # Define quick scan locations
            quick_scan_locations = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/AppData/Local/Temp")
            ]
            
            all_threats = []
            total_files_scanned = 0
            
            for location in quick_scan_locations:
                if Path(location).exists():
                    threats = self.file_scanner.scan_directory(location, recursive=False)
                    all_threats.extend(threats)
                    total_files_scanned += len(list(Path(location).rglob("*")))
            
            # Record scan history
            if user_id:
                await self._record_scan_history(
                    user_id=user_id,
                    scan_type=ScanType.QUICK,
                    scan_path="Quick Scan",
                    threats_found=len(all_threats),
                    scan_results={'threats': all_threats}
                )
            
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'scan_type': ScanType.QUICK,
                'scan_duration': scan_duration,
                'files_scanned': total_files_scanned,
                'threats_detected': all_threats,
                'scan_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error performing quick scan: {e}")
            return {
                'success': False,
                'scan_type': ScanType.QUICK,
                'error': str(e),
                'scan_time': datetime.now().isoformat()
            }
    
    async def full_scan(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Perform a full system scan.
        
        Args:
            user_id: ID of the user performing the scan
            
        Returns:
            Dictionary with scan results
        """
        start_time = datetime.now()
        
        try:
            # Define full scan locations (excluding system directories)
            system_drives = self._get_system_drives()
            all_threats = []
            total_files_scanned = 0
            
            for drive in system_drives:
                if Path(drive).exists():
                    threats = self.file_scanner.scan_directory(drive, recursive=True)
                    all_threats.extend(threats)
                    total_files_scanned += len(list(Path(drive).rglob("*")))
            
            # Record scan history
            if user_id:
                await self._record_scan_history(
                    user_id=user_id,
                    scan_type=ScanType.FULL,
                    scan_path="Full System Scan",
                    threats_found=len(all_threats),
                    scan_results={'threats': all_threats}
                )
            
            end_time = datetime.now()
            scan_duration = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'scan_type': ScanType.FULL,
                'scan_duration': scan_duration,
                'files_scanned': total_files_scanned,
                'threats_detected': all_threats,
                'scan_time': end_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error performing full scan: {e}")
            return {
                'success': False,
                'scan_type': ScanType.FULL,
                'error': str(e),
                'scan_time': datetime.now().isoformat()
            }
    
    async def _record_scan_history(self, user_id: int, scan_type: str, scan_path: str,
                                 threats_found: int, scan_results: Dict) -> None:
        """Record scan history in database."""
        try:
            db = next(get_db())
            scan_history = ScanHistory(
                user_id=user_id,
                scan_type=scan_type,
                scan_path=scan_path,
                start_time=datetime.now(),
                end_time=datetime.now(),
                threats_found=threats_found,
                scan_status="completed",
                scan_results=scan_results
            )
            db.add(scan_history)
            db.commit()
        except Exception as e:
            logger.error(f"Error recording scan history: {e}")
    
    def _get_system_drives(self) -> List[str]:
        """Get list of system drives to scan."""
        import string
        drives = []
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if Path(drive).exists():
                drives.append(drive)
        return drives
    
    async def get_scan_history(self, user_id: int, limit: int = 50) -> List[Dict]:
        """
        Get scan history for a user.
        
        Args:
            user_id: ID of the user
            limit: Maximum number of records to return
            
        Returns:
            List of scan history records
        """
        try:
            db = next(get_db())
            scans = db.query(ScanHistory).filter(
                ScanHistory.user_id == user_id
            ).order_by(ScanHistory.start_time.desc()).limit(limit).all()
            
            return [
                {
                    'id': scan.id,
                    'scan_type': scan.scan_type,
                    'scan_path': scan.scan_path,
                    'start_time': scan.start_time.isoformat(),
                    'end_time': scan.end_time.isoformat() if scan.end_time else None,
                    'threats_found': scan.threats_found,
                    'scan_status': scan.scan_status
                }
                for scan in scans
            ]
        except Exception as e:
            logger.error(f"Error getting scan history: {e}")
            return []
    
    async def update_signatures(self) -> Dict[str, Any]:
        """
        Update virus signatures.
        
        Returns:
            Dictionary with update results
        """
        try:
            success = self.detection_engine.update_signatures()
            return {
                'success': success,
                'message': 'Signatures updated successfully' if success else 'Failed to update signatures',
                'update_time': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error updating signatures: {e}")
            return {
                'success': False,
                'error': str(e),
                'update_time': datetime.now().isoformat()
            } 