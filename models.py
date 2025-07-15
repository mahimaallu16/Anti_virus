from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import time
import os
import base64
import re

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    scan_type = Column(String)  # quick, full, custom
    scan_path = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    threats_found = Column(Integer, default=0)
    scan_status = Column(String)  # completed, failed, in_progress
    scan_results = Column(JSON)

    user = relationship("User", back_populates="scans")

class Settings(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    real_time_protection = Column(Boolean, default=True)
    web_protection = Column(Boolean, default=True)
    email_protection = Column(Boolean, default=True)
    file_system_protection = Column(Boolean, default=True)
    network_protection = Column(Boolean, default=True)
    auto_quarantine = Column(Boolean, default=True)
    scan_schedule = Column(JSON)  # Store cron-like schedule
    excluded_paths = Column(JSON)  # List of paths to exclude from scanning

    user = relationship("User", back_populates="settings")

class Credentials(Base):
    __tablename__ = "credentials"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)  # Store hashed password for security

# Add relationships
User.scans = relationship("ScanHistory", back_populates="user")
User.settings = relationship("Settings", back_populates="user", uselist=False)

def is_suspicious_location(file_path):
    # Only flag if file is in temp and is new (<1 hour old)
    if "temp" in file_path.lower():
        file_age = time.time() - os.path.getctime(file_path)
        if file_age < 3600:  # 1 hour
            return True
    return False

def is_suspicious_static(file_path):
    # Example: flag if file is in temp and is new
    return is_suspicious_location(file_path)

def analyze_file_behavior(file_path):
    # Only run dynamic analysis if static checks are suspicious
    if is_suspicious_static(file_path):
        # (Optional) Use a sandbox here
        # Check for network connections, file writes, etc.
        pass
    return {'score': 0}

def is_obfuscated(content):
    # Look for very long base64 strings
    matches = re.findall(r'[A-Za-z0-9+/]{200,}={0,2}', content)
    for m in matches:
        try:
            decoded = base64.b64decode(m)
            # Check if decoded content is executable or script
            if b'MZ' in decoded or b'#!/' in decoded:
                return True
        except Exception:
            continue
    return False

def has_suspicious_powershell(content):
    # Only flag if both PowerShell and download/invoke-expression are present
    if re.search(r'powershell', content, re.IGNORECASE) and \
       re.search(r'(DownloadString|Invoke-Expression|IEX)', content, re.IGNORECASE):
        return True
    return False 