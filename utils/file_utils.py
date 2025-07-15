"""
File utility functions for antivirus system.

This module provides utility functions for file operations,
including hash calculation, archive handling, and file information.
"""

import os
import hashlib
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Union
import logging

try:
    import rarfile
except ImportError:
    rarfile = None

try:
    import py7zr
except ImportError:
    py7zr = None

logger = logging.getLogger(__name__)

def get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)
        
    Returns:
        Hexadecimal hash string
    """
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return ""

def is_archive_file(file_path: str) -> bool:
    """
    Check if a file is an archive.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file is an archive, False otherwise
    """
    archive_extensions = {
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        '.xz', '.cab', '.iso', '.dmg'
    }
    return Path(file_path).suffix.lower() in archive_extensions

def extract_archive(file_path: str, extract_dir: Optional[str] = None) -> List[str]:
    """
    Extract an archive file.
    
    Args:
        file_path: Path to the archive file
        extract_dir: Directory to extract to (default: temp directory)
        
    Returns:
        List of extracted file paths
    """
    extracted_files = []
    
    if not extract_dir:
        extract_dir = tempfile.mkdtemp()
    
    try:
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.zip':
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                extracted_files = [os.path.join(extract_dir, f) for f in zip_ref.namelist()]
        
        elif file_ext == '.rar' and rarfile:
            with rarfile.RarFile(file_path, 'r') as rar_ref:
                rar_ref.extractall(extract_dir)
                extracted_files = [os.path.join(extract_dir, f) for f in rar_ref.namelist()]
        
        elif file_ext == '.7z' and py7zr:
            with py7zr.SevenZipFile(file_path, 'r') as sz_ref:
                sz_ref.extractall(extract_dir)
                extracted_files = [os.path.join(extract_dir, f) for f in sz_ref.getnames()]
        
        else:
            logger.warning(f"Unsupported archive format: {file_ext}")
            
    except Exception as e:
        logger.error(f"Error extracting archive {file_path}: {e}")
    
    return extracted_files

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def get_file_info(file_path: str) -> Dict[str, Union[str, int, float]]:
    """
    Get comprehensive file information.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with file information
    """
    try:
        stat = os.stat(file_path)
        path_obj = Path(file_path)
        
        return {
            'name': path_obj.name,
            'extension': path_obj.suffix,
            'size': stat.st_size,
            'size_formatted': format_file_size(stat.st_size),
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime,
            'hash': get_file_hash(file_path),
            'is_file': path_obj.is_file(),
            'is_directory': path_obj.is_dir(),
            'exists': path_obj.exists(),
            'absolute_path': str(path_obj.absolute()),
            'parent': str(path_obj.parent)
        }
    except Exception as e:
        logger.error(f"Error getting file info for {file_path}: {e}")
        return {}

def safe_filename(filename: str) -> str:
    """
    Convert filename to a safe version.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
    """
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    safe_name = filename
    for char in unsafe_chars:
        safe_name = safe_name.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    safe_name = safe_name.strip(' .')
    
    # Ensure filename is not empty
    if not safe_name:
        safe_name = "unnamed_file"
    
    return safe_name

def copy_file_safely(source: str, destination: str) -> bool:
    """
    Safely copy a file with error handling.
    
    Args:
        source: Source file path
        destination: Destination file path
        
    Returns:
        True if copy successful, False otherwise
    """
    try:
        # Ensure destination directory exists
        dest_dir = Path(destination).parent
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        shutil.copy2(source, destination)
        return True
    except Exception as e:
        logger.error(f"Error copying file from {source} to {destination}: {e}")
        return False

def move_file_safely(source: str, destination: str) -> bool:
    """
    Safely move a file with error handling.
    
    Args:
        source: Source file path
        destination: Destination file path
        
    Returns:
        True if move successful, False otherwise
    """
    try:
        # Ensure destination directory exists
        dest_dir = Path(destination).parent
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Move file
        shutil.move(source, destination)
        return True
    except Exception as e:
        logger.error(f"Error moving file from {source} to {destination}: {e}")
        return False

def delete_file_safely(file_path: str) -> bool:
    """
    Safely delete a file with error handling.
    
    Args:
        file_path: Path to the file to delete
        
    Returns:
        True if deletion successful, False otherwise
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting file {file_path}: {e}")
        return False

def get_directory_size(directory: str) -> int:
    """
    Calculate total size of a directory.
    
    Args:
        directory: Directory path
        
    Returns:
        Total size in bytes
    """
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                if os.path.exists(file_path):
                    total_size += os.path.getsize(file_path)
    except Exception as e:
        logger.error(f"Error calculating directory size for {directory}: {e}")
    
    return total_size

def list_files_recursive(directory: str, extensions: Optional[List[str]] = None) -> List[str]:
    """
    List all files in a directory recursively.
    
    Args:
        directory: Directory path
        extensions: Optional list of file extensions to filter by
        
    Returns:
        List of file paths
    """
    files = []
    try:
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if extensions:
                    if any(file_path.lower().endswith(ext.lower()) for ext in extensions):
                        files.append(file_path)
                else:
                    files.append(file_path)
    except Exception as e:
        logger.error(f"Error listing files in {directory}: {e}")
    
    return files 