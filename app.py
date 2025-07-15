import os
import shutil
import json
from fastapi import FastAPI, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import yara
from datetime import datetime
import glob
import re
import base64
import zipfile
import tempfile
import hashlib
import requests
import subprocess
import time
from pathlib import Path
from typing import Dict, List
import asyncio
from enum import Enum
try:
    import rarfile
except ImportError:
    rarfile = None
try:
    import py7zr
except ImportError:
    py7zr = None

# Import enterprise YARA engine
try:
    from enterprise_yara_engine import EnterpriseYaraEngine
    ENTERPRISE_YARA_AVAILABLE = True
except ImportError:
    ENTERPRISE_YARA_AVAILABLE = False
    print("Enterprise YARA engine not available, using basic YARA")

from database import get_db
from models import Settings, User
from sqlalchemy.orm import Session
from fastapi import Depends

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
QUARANTINE_DIR = "quarantine"
QUARANTINE_DB = "quarantine_db.json"
QUARANTINE_SCORE_THRESHOLD = 80

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Enhanced quarantine configuration
QUARANTINE_CONFIG = {
    "auto_quarantine_threshold": 80,  # Score above which files are auto-quarantined
    "alert_threshold": 60,            # Score above which alerts are shown
    "max_quarantine_size": 1024 * 1024 * 100,  # 100MB max quarantine size
    "retention_days": 30,             # How long to keep quarantined files
    "enable_notifications": True,     # Enable real-time notifications
    "backup_before_delete": True,     # Backup files before permanent deletion
}

# Alert severity levels
class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Global alert system
active_alerts = []
connected_clients = []

# Whitelist system for reducing false positives
WHITELISTED_PATHS = {
    # System directories that are normally safe
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

# Known safe file hashes (you can populate this from your system)
SAFE_FILE_HASHES = set()

# Initialize quarantine database
def load_quarantine_db():
    if os.path.exists(QUARANTINE_DB):
        with open(QUARANTINE_DB, 'r') as f:
            return json.load(f)
    return []

def save_quarantine_db(data):
    with open(QUARANTINE_DB, 'w') as f:
        json.dump(data, f, indent=2)

# Load all YARA rules from signatures directory
YARA_RULES_PATHS = glob.glob(os.path.join("signatures", "*.yar"))
try:
    yara_rules = yara.compile(filepaths={os.path.basename(p): p for p in YARA_RULES_PATHS})
except Exception as e:
    yara_rules = None
    print(f"Failed to load YARA rules: {e}")

# Add a global variable to store logs
activity_logs = [
    {"timestamp": "2024-06-01T12:00:00", "message": "Scan started"},
    {"timestamp": "2024-06-01T12:05:00", "message": "Threat detected"},
    {"timestamp": "2024-06-01T12:10:00", "message": "Scan completed"}
]

VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY')
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'

def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_virustotal(sha256):
    if not VIRUSTOTAL_API_KEY:
        return None
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_URL + sha256
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'vt_link': f'https://www.virustotal.com/gui/file/{sha256}/detection'
            }
        else:
            return None
    except Exception as e:
        return None

# Digital signature verification
def is_digitally_signed(file_path):
    """Check if a file has a valid digital signature"""
    try:
        if not file_path.lower().endswith(('.exe', '.dll', '.sys', '.ocx')):
            return False
        
        # Use PowerShell to check digital signature
        result = subprocess.run([
            'powershell', '-Command', 
            f'Get-AuthenticodeSignature "{file_path}" | Select-Object Status'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            output = result.stdout.lower()
            return 'valid' in output and 'notsigned' not in output
        return False
    except Exception:
        return False

def is_whitelisted_file(file_path):
    """Check if file is in whitelist based on path, extension, and signature"""
    try:
        file_path = os.path.abspath(file_path)
        
        # Check whitelisted paths
        for whitelisted_path in WHITELISTED_PATHS:
            if file_path.lower().startswith(whitelisted_path.lower()):
                return True
        
        # Check whitelisted extensions
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in WHITELISTED_EXTENSIONS:
            return True
        
        # Check digital signature
        if is_digitally_signed(file_path):
            return True
        
        # Check known safe hashes
        file_hash = get_sha256(file_path)
        if file_hash in SAFE_FILE_HASHES:
            return True
        
        return False
    except Exception:
        return False

def is_legitimate_powershell_script(content, file_path):
    """Enhanced PowerShell detection that reduces false positives"""
    try:
        # Check if it's a legitimate admin script
        if any(keyword in content.lower() for keyword in [
            'get-service', 'get-process', 'get-computerinfo', 
            'get-wmiobject', 'get-ciminstance', 'export-csv',
            'import-csv', 'get-content', 'set-content', 'out-file'
        ]):
            # If it contains legitimate admin commands, require more suspicious indicators
            suspicious_patterns = [
                r'(Invoke-Expression|IEX)\s*\(',  # Dynamic execution
                r'DownloadString\s*\(',           # Downloads
                r'FromBase64String\s*\(',         # Base64 decoding
                r'New-Object\s+System\.Net\.WebClient',  # Web client
                r'Start-Process\s+.*\s+-WindowStyle\s+Hidden',  # Hidden execution
            ]
            
            suspicious_count = sum(1 for pattern in suspicious_patterns 
                                 if re.search(pattern, content, re.IGNORECASE))
            
            # Only flag if multiple suspicious patterns are found
            return suspicious_count >= 2
        
        # For regular PowerShell scripts, use original logic but with context
        suspicious_commands = [
            r'Invoke-Expression\s*\(', 
            r'IEX\s*\(',
            r'DownloadString\s*\(',
            r'FromBase64String\s*\(',
            r'New-Object\s+System\.Net\.WebClient'
        ]
        
        return any(re.search(cmd, content, re.IGNORECASE) for cmd in suspicious_commands)
    except Exception:
        return False

def is_legitimate_obfuscation(content, file_path):
    """Enhanced obfuscation detection that reduces false positives"""
    try:
        # Look for very long base64 strings (more than 200 chars)
        base64_matches = re.findall(r'[A-Za-z0-9+/]{200,}={0,2}', content)
        
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match)
                
                # Check if decoded content contains executable patterns
                if (b'MZ' in decoded[:2] or  # PE header
                    b'#!/' in decoded or     # Script shebang
                    b'powershell' in decoded.lower() or
                    b'cmd.exe' in decoded.lower() or
                    b'exec' in decoded.lower()):
                    return True
                    
            except Exception:
                continue
        
        # Check for other obfuscation techniques
        obfuscation_patterns = [
            r'eval\s*\([^)]*\)',           # eval() calls
            r'unescape\s*\([^)]*\)',       # unescape() calls
            r'String\.fromCharCode\s*\(',  # Character code conversion
            r'\\x[0-9a-fA-F]{2}',         # Hex encoding
            r'\\u[0-9a-fA-F]{4}',         # Unicode encoding
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) 
                  for pattern in obfuscation_patterns)
    except Exception:
        return False

def is_legitimate_api_usage(content, file_path):
    """Enhanced API detection that reduces false positives"""
    try:
        dangerous_apis = [
            'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory', 
            'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
            'CreateProcess', 'ShellExecute', 'WinExec'
        ]
        
        # Count dangerous API usage
        api_count = sum(1 for api in dangerous_apis if api in content)
        
        # Only flag if multiple dangerous APIs are used together
        if api_count >= 2:
            # Additional check: look for suspicious combinations
            suspicious_combinations = [
                ('VirtualAlloc', 'WriteProcessMemory'),
                ('LoadLibrary', 'GetProcAddress'),
                ('CreateRemoteThread', 'VirtualAlloc'),
            ]
            
            for combo in suspicious_combinations:
                if all(api in content for api in combo):
                    return True
        
        return False
    except Exception:
        return False

def analyze_file_context(file_path):
    """Analyze file context to reduce false positives"""
    try:
        context_score = 0
        file_path_lower = file_path.lower()
        
        # Check file age (newer files are more suspicious)
        try:
            file_age = time.time() - os.path.getctime(file_path)
            if file_age < 3600:  # Less than 1 hour
                context_score += 20
            elif file_age < 86400:  # Less than 1 day
                context_score += 10
        except Exception:
            pass
        
        # Check file location
        suspicious_locations = ['temp', 'tmp', 'downloads', 'desktop']
        if any(loc in file_path_lower for loc in suspicious_locations):
            context_score += 15
        
        # Check file size (very small executables are suspicious)
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 1024 and file_path_lower.endswith('.exe'):  # < 1KB
                context_score += 25
        except Exception:
            pass
        
        # Check if file is in system directories (less suspicious)
        system_dirs = ['system32', 'syswow64', 'program files']
        if any(dir_name in file_path_lower for dir_name in system_dirs):
            context_score -= 30
        
        return max(0, context_score)
    except Exception:
        return 0

def is_obfuscated(content):
    """Legacy function - now calls enhanced version"""
    return is_legitimate_obfuscation(content, "")

def has_suspicious_powershell(content):
    """Legacy function - now calls enhanced version"""
    return is_legitimate_powershell_script(content, "")

def has_dangerous_apis(content):
    """Legacy function - now calls enhanced version"""
    return is_legitimate_api_usage(content, "")

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    file_location = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_location, "wb") as f:
        f.write(await file.read())
    return {"filename": file.filename, "path": file_location}

@app.post("/api/scan")
async def scan(request: Request):
    data = await request.json()
    file_path = data.get("path")
    scan_type = data.get("type", "Unknown")
    threats = []
    scanned_files = 0
    yara_matches = []  # Initialize yara_matches
    vt_result = None   # Initialize vt_result
    
    # Handle different scan types
    if scan_type in ["quick", "full", "system"]:
        # Simulate scanning different areas based on scan type
        if scan_type == "quick":
            # Quick scan - check common locations
            common_paths = [
                os.path.join(os.getcwd(), "uploads"),
                os.path.join(os.getcwd(), "temp"),
                os.path.join(os.getcwd(), "downloads")
            ]
            scanned_files = len(common_paths)
            
            # Simulate finding some threats
            threats.append({
                "path": "C:/temp/suspicious.exe",
                "threat": "Suspicious executable in temp folder",
                "score": 75
            })
            
        elif scan_type == "full":
            # Full scan - check entire system
            scanned_files = 1500  # Simulate scanning many files
            
            # Simulate finding multiple threats
            threats.extend([
                {
                    "path": "C:/Downloads/malware.zip",
                    "threat": "Malware detected in downloads",
                    "score": 90
                },
                {
                    "path": "C:/Users/Desktop/suspicious.js",
                    "threat": "Suspicious JavaScript file",
                    "score": 60
                }
            ])
            
        elif scan_type == "system":
            # System scan - check system directories
            scanned_files = 800
            
            # Simulate system-level threats
            threats.append({
                "path": "C:/Windows/System32/suspicious.dll",
                "threat": "Suspicious DLL in system directory",
                "score": 85
            })
    
    # Handle custom path scanning
    elif file_path and os.path.exists(file_path):
        scanned_files = 1
        
        # YARA signature matching
        if yara_rules:
            try:
                matches = yara_rules.match(file_path)
                for match in matches:
                    yara_matches.append({
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": match.strings
                    })
                    
                    # Check if file is whitelisted before flagging
                    if not is_whitelisted_file(file_path):
                        threats.append({
                            "path": file_path,
                            "threat": f"Signature: {match.rule}",
                            "score": 95,
                            "details": {
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "meta": match.meta,
                                "strings": match.strings
                            }
                        })
            except Exception as e:
                pass
        
        # Enhanced behavior-based detection with advanced analysis
        if not is_whitelisted_file(file_path):
            # Perform advanced behavioral analysis
            behavior_results = analyze_advanced_behavior(file_path)
            context_analysis = analyze_behavioral_context(file_path, behavior_results)
            
            # Only flag if behavioral analysis indicates significant risk
            if behavior_results["score"] > 0:
                # Use context-adjusted score for final decision
                final_score = context_analysis["adjusted_score"]
                
                if final_score >= 40:  # Lower threshold for behavioral detection
                    threat_description = f"Behavioral: {', '.join(behavior_results['behaviors'])} (Risk: {context_analysis['final_risk_level']})"
                    
                    threats.append({
                        "path": file_path,
                        "threat": threat_description,
                        "score": min(90, final_score + 30),  # Cap at 90 for behavioral
                        "details": {
                            "behavioral_analysis": behavior_results,
                            "context_analysis": context_analysis,
                            "detection_type": "advanced_behavioral"
                        }
                    })
            
        # Archive scanning
        archive_exts = ['.zip', '.rar', '.7z']
        if any(file_path.lower().endswith(ext) for ext in archive_exts):
            archive_threats = scan_archive(file_path)
            if archive_threats:
                threats.extend(archive_threats)
        
        # VirusTotal check
        sha256 = get_sha256(file_path)
        vt_result = check_virustotal(sha256)
        if vt_result and vt_result.get('malicious', 0) > 0:
            threats.append({
                "path": file_path,
                "threat": "VirusTotal: Known malicious hash",
                "score": 100,
                "details": {"virustotal": vt_result}
            })
    
    # If no threats found for any scan type, add a clean result
    if not threats:
        threats.append({
            "path": "Scan completed",
            "threat": "No threats detected",
            "score": 0
        })
    
    # Log the scan action
    activity_logs.append({
        "timestamp": datetime.now().isoformat(),
        "message": f"{scan_type.capitalize()} scan performed - {scanned_files} files scanned, {len([t for t in threats if t['score'] > 0])} threats found"
    })
    
    # Auto-quarantine high-risk files that actually exist
    auto_quarantined = []
    for threat in threats:
        if threat.get('score', 0) >= QUARANTINE_SCORE_THRESHOLD:
            # Only quarantine files that actually exist
            if os.path.exists(threat['path']):
                qrec = quarantine_file_internal(threat['path'], threat)
                if qrec:
                    auto_quarantined.append(qrec)
            else:
                # For simulated threats that don't exist, create an alert but don't quarantine
                file_name = os.path.basename(threat['path'])
                file_extension = os.path.splitext(file_name)[1].lower()
                file_type, risk_level = determine_file_risk(file_extension, threat.get("score", 0))
                severity = determine_alert_severity(threat.get("score", 0), risk_level)
                
                alert_title = f"⚠️ Threat Detected (Simulated): {file_name}"
                alert_message = f"A {risk_level} risk file was detected but could not be quarantined (file not found). Threat score: {threat.get('score', 0)}/100"
                
                create_alert(severity, alert_title, alert_message, {
                    "filename": file_name,
                    "file_type": file_type,
                    "threat_score": threat.get("score", 0),
                    "threat_type": threat.get("threat", "Unknown"),
                    "note": "Simulated threat - file not found"
                })
    
    return {
        "threats": threats,
        "scanned_files": scanned_files,
        "threats_found": len([t for t in threats if t["score"] > 0]),
        "scan_type": scan_type,
        "yara_matches": yara_matches,
        "virustotal": vt_result,
        "auto_quarantined": auto_quarantined
    }

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/api/metrics")
def get_metrics():
    return {
        "cpu": 10,
        "ram": 20,
        "disk": 30
    }

@app.get("/api/logs")
def get_logs():
    return activity_logs

@app.get("/api/quarantine")
def get_quarantine():
    """Get all quarantined files with enhanced information"""
    quarantine_db = load_quarantine_db()
    
    # Add additional information for each file
    for record in quarantine_db:
        # Check if file still exists in quarantine
        record["exists"] = os.path.exists(record["quarantine_path"])
        
        # Calculate file age
        quarantine_date = datetime.fromisoformat(record["quarantine_date"])
        age_days = (datetime.now() - quarantine_date).days
        record["age_days"] = age_days
        
        # Format file size
        record["file_size_formatted"] = format_file_size(record["file_size"])
    
    return {
        "files": quarantine_db,
        "total_count": len(quarantine_db),
        "total_size": sum(r["file_size"] for r in quarantine_db),
        "config": QUARANTINE_CONFIG
    }

@app.post("/api/quarantine")
async def quarantine_file(request: Request):
    """Enhanced quarantine endpoint with better error handling and alerts"""
    data = await request.json()
    file_path = data.get("file_path")
    
    if not file_path or not os.path.exists(file_path):
        return JSONResponse(
            status_code=404,
            content={"detail": "File not found"}
        )
    
    try:
        # Get file information
        file_name = os.path.basename(file_path)
        file_extension = os.path.splitext(file_name)[1].lower()
        file_size = os.path.getsize(file_path)
        
        # Determine file type and risk level
        threat_score = data.get("threat_score", 0)
        file_type, risk_level = determine_file_risk(file_extension, threat_score)
        
        # Create quarantine filename with timestamp and hash
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = get_sha256(file_path)[:8]  # First 8 characters of hash
        quarantine_filename = f"{timestamp}_{file_hash}_{file_name}"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)
        
        # Move file to quarantine
        shutil.move(file_path, quarantine_path)
        
        # Create enhanced quarantine record
        quarantine_record = {
            "id": f"quarantine_{int(time.time())}",
            "original_path": file_path,
            "quarantine_path": quarantine_path,
            "filename": file_name,
            "file_type": file_type,
            "file_extension": file_extension,
            "file_size": file_size,
            "file_hash": get_sha256(file_path),
            "threat_score": threat_score,
            "threat_type": data.get("threat_type", "Unknown"),
            "threat_details": data.get("threat_details", {}),
            "quarantine_reason": data.get("quarantine_reason", "Suspicious file"),
            "risk_level": risk_level,
            "quarantine_date": datetime.now().isoformat(),
            "status": "quarantined",
            "restore_count": 0,
            "last_restored": None,
            "backup_path": None
        }
        
        # Add to quarantine database
        quarantine_db = load_quarantine_db()
        quarantine_db.append(quarantine_record)
        save_quarantine_db(quarantine_db)
        
        # Create appropriate alert based on severity
        severity = determine_alert_severity(threat_score, risk_level)
        alert_title = f"🚨 Threat Detected: {file_name}"
        alert_message = f"A {risk_level} risk file has been quarantined. Threat score: {threat_score}/100"
        
        create_alert(severity, alert_title, alert_message, {
            "filename": file_name,
            "file_type": file_type,
            "threat_score": threat_score,
            "threat_type": data.get("threat_type", "Unknown"),
            "quarantine_id": quarantine_record["id"]
        })
        
        # Log the quarantine action
        activity_logs.append({
            "timestamp": datetime.now().isoformat(),
            "message": f"File quarantined: {file_name} ({file_type}) - Score: {quarantine_record['threat_score']} - Risk: {risk_level}",
            "type": "quarantine",
            "severity": severity.value
        })
        
        return {
            "message": f"File quarantined successfully. Risk level: {risk_level}",
            "quarantine_record": quarantine_record,
            "alert_created": True
        }
        
    except Exception as e:
        error_msg = f"Error quarantining file: {str(e)}"
        create_alert(AlertSeverity.HIGH, "Quarantine Error", error_msg)
        return JSONResponse(
            status_code=500,
            content={"detail": error_msg}
        )

@app.delete("/api/quarantine/{quarantine_id}")
def delete_quarantined_file(quarantine_id: str):
    """Enhanced delete endpoint with backup option"""
    try:
        quarantine_db = load_quarantine_db()
        
        # Find the file in quarantine database
        file_record = None
        for record in quarantine_db:
            if record["id"] == quarantine_id:
                file_record = record
                break
        
        if not file_record:
            return JSONResponse(
                status_code=404,
                content={"detail": "File not found in quarantine"}
            )
        
        # Create backup if enabled
        if QUARANTINE_CONFIG["backup_before_delete"] and os.path.exists(file_record["quarantine_path"]):
            backup_dir = os.path.join(QUARANTINE_DIR, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            backup_path = os.path.join(backup_dir, f"deleted_{file_record['filename']}")
            shutil.copy2(file_record["quarantine_path"], backup_path)
            file_record["backup_path"] = backup_path
        
        # Delete the file from quarantine directory
        if os.path.exists(file_record["quarantine_path"]):
            os.remove(file_record["quarantine_path"])
        
        # Remove from database
        quarantine_db = [r for r in quarantine_db if r["id"] != quarantine_id]
        save_quarantine_db(quarantine_db)
        
        # Create alert for deletion
        create_alert(
            AlertSeverity.MEDIUM,
            "🗑️ File Deleted from Quarantine",
            f"File '{file_record['filename']}' has been permanently deleted from quarantine.",
            {"filename": file_record["filename"], "file_type": file_record["file_type"]}
        )
        
        # Log the deletion
        activity_logs.append({
            "timestamp": datetime.now().isoformat(),
            "message": f"File deleted from quarantine: {file_record['filename']}",
            "type": "delete",
            "severity": "medium"
        })
        
        return {"message": "File deleted from quarantine"}
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Error deleting file: {str(e)}"}
        )

@app.post("/api/restore")
async def restore_file(request: Request):
    """Enhanced restore endpoint with safety checks"""
    data = await request.json()
    quarantine_id = data.get("quarantine_id")
    
    try:
        quarantine_db = load_quarantine_db()
        
        # Find the file in quarantine database
        file_record = None
        for record in quarantine_db:
            if record["id"] == quarantine_id:
                file_record = record
                break
        
        if not file_record:
            return JSONResponse(
                status_code=404,
                content={"detail": "File not found in quarantine"}
            )
        
        # Check if file exists in quarantine
        if not os.path.exists(file_record["quarantine_path"]):
            return JSONResponse(
                status_code=404,
                content={"detail": "Quarantined file not found on disk"}
            )
        
        # Check if original location is safe to restore to
        original_dir = os.path.dirname(file_record["original_path"])
        if not os.path.exists(original_dir):
            os.makedirs(original_dir, exist_ok=True)
        
        # Check if there's already a file at the original location
        if os.path.exists(file_record["original_path"]):
            # Create backup of existing file
            backup_path = file_record["original_path"] + f".backup_{int(time.time())}"
            shutil.move(file_record["original_path"], backup_path)
        
        # Restore the file
        shutil.move(file_record["quarantine_path"], file_record["original_path"])
        
        # Update restore count and timestamp
        file_record["restore_count"] += 1
        file_record["last_restored"] = datetime.now().isoformat()
        
        # Remove from quarantine database
        quarantine_db = [r for r in quarantine_db if r["id"] != quarantine_id]
        save_quarantine_db(quarantine_db)
        
        # Create alert for restoration
        create_alert(
            AlertSeverity.MEDIUM,
            "✅ File Restored from Quarantine",
            f"File '{file_record['filename']}' has been restored to its original location.",
            {"filename": file_record["filename"], "file_type": file_record["file_type"]}
        )
        
        # Log the restoration
        activity_logs.append({
            "timestamp": datetime.now().isoformat(),
            "message": f"File restored from quarantine: {file_record['filename']}",
            "type": "restore",
            "severity": "medium"
        })
        
        return {"message": "File restored successfully"}
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": f"Error restoring file: {str(e)}"}
        )

@app.get("/api/protection")
def get_protection(db: Session = Depends(get_db)):
    # For demo, use the first user (id=1)
    settings = db.query(Settings).filter(Settings.user_id == 1).first()
    if not settings:
        # Create default settings for user 1 if not exist
        settings = Settings(user_id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return {
        "real_time": settings.real_time_protection,
        "web": settings.web_protection,
        "email": settings.email_protection,
        "file_system": settings.file_system_protection,
        "network": settings.network_protection
    }

@app.post("/api/protection")
async def update_protection(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    setting = data.get("setting")
    enabled = data.get("enabled")
    settings = db.query(Settings).filter(Settings.user_id == 1).first()
    if not settings:
        settings = Settings(user_id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    # Map frontend keys to model attributes
    mapping = {
        "real_time": "real_time_protection",
        "web": "web_protection",
        "email": "email_protection",
        "file_system": "file_system_protection",
        "network": "network_protection"
    }
    attr = mapping.get(setting)
    if attr:
        setattr(settings, attr, enabled)
        db.commit()
        db.refresh(settings)
    return {
        "real_time": settings.real_time_protection,
        "web": settings.web_protection,
        "email": settings.email_protection,
        "file_system": settings.file_system_protection,
        "network": settings.network_protection
    }

@app.get("/api/quarantine/stats")
def get_quarantine_stats():
    """Enhanced quarantine statistics"""
    quarantine_db = load_quarantine_db()
    
    # File type statistics
    file_types = {}
    threat_scores = []
    threat_types = {}
    risk_levels = {}
    
    for record in quarantine_db:
        # Count file types
        file_type = record.get("file_type", "Unknown")
        file_types[file_type] = file_types.get(file_type, 0) + 1
        
        # Collect threat scores
        threat_scores.append(record.get("threat_score", 0))
        
        # Count threat types
        threat_type = record.get("threat_type", "Unknown")
        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Count risk levels
        risk_level = record.get("risk_level", "Unknown")
        risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
    
    return {
        "total_quarantined": len(quarantine_db),
        "total_size": sum(r["file_size"] for r in quarantine_db),
        "file_types": file_types,
        "threat_types": threat_types,
        "risk_levels": risk_levels,
        "average_threat_score": sum(threat_scores) / len(threat_scores) if threat_scores else 0,
        "max_threat_score": max(threat_scores) if threat_scores else 0,
        "min_threat_score": min(threat_scores) if threat_scores else 0,
        "alerts": {
            "total": len(active_alerts),
            "unacknowledged": len([a for a in active_alerts if not a["acknowledged"]]),
            "by_severity": {
                "critical": len([a for a in active_alerts if a["severity"] == "critical"]),
                "high": len([a for a in active_alerts if a["severity"] == "high"]),
                "medium": len([a for a in active_alerts if a["severity"] == "medium"]),
                "low": len([a for a in active_alerts if a["severity"] == "low"])
            }
        }
    }

# WebSocket endpoint for real-time alerts
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

# Utility functions
def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def scan_archive(file_path):
    results = []
    temp_dir = tempfile.mkdtemp()
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(temp_dir)
        elif rarfile and rarfile.is_rarfile(file_path):
            with rarfile.RarFile(file_path) as r:
                r.extractall(temp_dir)
        elif py7zr and file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as z:
                z.extractall(temp_dir)
        else:
            return []
        # Walk extracted files and scan each
        for root, dirs, files in os.walk(temp_dir):
            for name in files:
                full_path = os.path.join(root, name)
                # Reuse your scan logic for each file
                # Only YARA/heuristics for now
                yara_matches = []
                threats = []
                if yara_rules:
                    try:
                        matches = yara_rules.match(full_path)
                        for match in matches:
                            yara_matches.append({
                                "rule": match.rule,
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "meta": match.meta,
                                "strings": match.strings
                            })
                            threats.append({
                                "path": full_path,
                                "threat": f"Signature: {match.rule}",
                                "score": 95,
                                "details": {
                                    "namespace": match.namespace,
                                    "tags": match.tags,
                                    "meta": match.meta,
                                    "strings": match.strings
                                }
                            })
                    except Exception as e:
                        pass
                # Heuristic checks
                try:
                    with open(full_path, 'rb') as f:
                        raw = f.read()
                        try:
                            content = raw.decode(errors='ignore')
                        except Exception:
                            content = ''
                    if is_obfuscated(content):
                        threats.append({
                            "path": full_path,
                            "threat": "Heuristic: Obfuscated content (long base64 string)",
                            "score": 80,
                            "details": {"heuristic": "obfuscation"}
                        })
                    if has_suspicious_powershell(content):
                        threats.append({
                            "path": full_path,
                            "threat": "Heuristic: Suspicious PowerShell command",
                            "score": 75,
                            "details": {"heuristic": "powershell"}
                        })
                    if has_dangerous_apis(content):
                        threats.append({
                            "path": full_path,
                            "threat": "Heuristic: Dangerous Windows API usage",
                            "score": 85,
                            "details": {"heuristic": "dangerous_api"}
                        })
                except Exception as e:
                    pass
                if threats:
                    results.extend(threats)
        return results
    finally:
        shutil.rmtree(temp_dir) 

def quarantine_file_internal(file_path, threat):
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        file_name = os.path.basename(file_path)
        file_extension = os.path.splitext(file_name)[1].lower()
        file_size = os.path.getsize(file_path)
        
        # Determine file type and risk level
        file_type, risk_level = determine_file_risk(file_extension, threat.get("score", 0))
        
        # Create quarantine filename with timestamp and hash
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = get_sha256(file_path)[:8]  # First 8 characters of hash
        quarantine_filename = f"{timestamp}_{file_hash}_{file_name}"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)
        
        # Move file to quarantine
        shutil.move(file_path, quarantine_path)
        
        # Create enhanced quarantine record
        quarantine_record = {
            "id": f"quarantine_{int(time.time())}",
            "original_path": file_path,
            "quarantine_path": quarantine_path,
            "filename": file_name,
            "file_type": file_type,
            "file_extension": file_extension,
            "file_size": file_size,
            "file_hash": get_sha256(file_path),
            "threat_score": threat.get("score", 0),
            "threat_type": threat.get("threat", "Unknown"),
            "threat_details": threat.get("details", {}),
            "quarantine_reason": threat.get("threat", "Suspicious file"),
            "risk_level": risk_level,
            "quarantine_date": datetime.now().isoformat(),
            "status": "quarantined",
            "restore_count": 0,
            "last_restored": None,
            "backup_path": None
        }
        
        # Add to quarantine database
        quarantine_db = load_quarantine_db()
        quarantine_db.append(quarantine_record)
        save_quarantine_db(quarantine_db)
        
        # Create appropriate alert based on severity
        threat_score = threat.get("score", 0)
        severity = determine_alert_severity(threat_score, risk_level)
        alert_title = f"🚨 Threat Detected: {file_name}"
        alert_message = f"A {risk_level} risk file has been quarantined. Threat score: {threat_score}/100"
        
        create_alert(severity, alert_title, alert_message, {
            "filename": file_name,
            "file_type": file_type,
            "threat_score": threat_score,
            "threat_type": threat.get("threat", "Unknown"),
            "quarantine_id": quarantine_record["id"]
        })
        
        # Log the quarantine action
        activity_logs.append({
            "timestamp": datetime.now().isoformat(),
            "message": f"File quarantined: {file_name} ({file_type}) - Score: {quarantine_record['threat_score']} - Risk: {risk_level}",
            "type": "quarantine",
            "severity": severity.value
        })
        
        return quarantine_record
    except Exception as e:
        print(f"Error in quarantine_file_internal: {str(e)}")
        return None

def analyze_advanced_behavior(file_path: str) -> Dict:
    """Advanced behavioral analysis similar to enterprise solutions"""
    try:
        behavior_results = {
            "score": 0,
            "behaviors": [],
            "confidence": 0,
            "risk_level": "low",
            "details": {}
        }
        
        # Read file content for analysis
        with open(file_path, 'rb') as f:
            content = f.read()
            try:
                text_content = content.decode(errors='ignore')
            except:
                text_content = ""
        
        # 1. Process Injection Detection
        injection_patterns = {
            "CreateRemoteThread": r"CreateRemoteThread",
            "VirtualAlloc": r"VirtualAlloc",
            "WriteProcessMemory": r"WriteProcessMemory",
            "NtCreateThreadEx": r"NtCreateThreadEx",
            "RtlCreateUserThread": r"RtlCreateUserThread",
            "SetWindowsHookEx": r"SetWindowsHookEx",
            "QueueUserAPC": r"QueueUserAPC"
        }
        
        injection_score = 0
        detected_injections = []
        for pattern_name, pattern in injection_patterns.items():
            if re.search(pattern, text_content, re.IGNORECASE):
                injection_score += 15
                detected_injections.append(pattern_name)
        
        if injection_score > 0:
            behavior_results["behaviors"].append("process_injection")
            behavior_results["score"] += injection_score
            behavior_results["details"]["injection_methods"] = detected_injections
        
        # 2. Persistence Mechanisms
        persistence_patterns = {
            "registry_modification": [
                r"RegCreateKey", r"RegSetValue", r"RegOpenKey",
                r"HKEY_LOCAL_MACHINE", r"HKEY_CURRENT_USER",
                r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ],
            "service_creation": [
                r"CreateService", r"StartService", r"OpenService",
                r"ServiceMain", r"SERVICE_AUTO_START"
            ],
            "scheduled_task": [
                r"CreateScheduledTask", r"RegisterTask", r"schtasks",
                r"TaskScheduler", r"ITaskScheduler"
            ],
            "startup_folder": [
                r"Startup", r"Start Menu\\Programs\\Startup",
                r"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            ]
        }
        
        persistence_score = 0
        detected_persistence = []
        for persistence_type, patterns in persistence_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    persistence_score += 10
                    detected_persistence.append(persistence_type)
                    break
        
        if persistence_score > 0:
            behavior_results["behaviors"].append("persistence")
            behavior_results["score"] += persistence_score
            behavior_results["details"]["persistence_methods"] = detected_persistence
        
        # 3. Network Communication Analysis
        network_patterns = {
            "http_requests": [
                r"HttpSendRequest", r"WinHttpSendRequest", r"HttpOpenRequest",
                r"URLDownloadToFile", r"URLDownloadToCacheFile"
            ],
            "socket_operations": [
                r"socket\s*\(", r"connect\s*\(", r"WSAConnect",
                r"send\s*\(", r"recv\s*\(", r"bind\s*\("
            ],
            "dns_queries": [
                r"gethostbyname", r"getaddrinfo", r"WSAAsyncGetHostByName",
                r"DNS_QUERY", r"ResolveHost"
            ],
            "url_patterns": [
                r"https?://[^\s\"']+", r"ftp://[^\s\"']+",
                r"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
            ]
        }
        
        network_score = 0
        detected_network = []
        for network_type, patterns in network_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    network_score += 8
                    detected_network.append(network_type)
                    break
        
        if network_score > 0:
            behavior_results["behaviors"].append("network_communication")
            behavior_results["score"] += network_score
            behavior_results["details"]["network_methods"] = detected_network
        
        # 4. Evasion Techniques Detection
        evasion_patterns = {
            "debugger_detection": [
                r"IsDebuggerPresent", r"CheckRemoteDebuggerPresent",
                r"NtQueryInformationProcess", r"PEB.BeingDebugged"
            ],
            "timing_checks": [
                r"GetTickCount", r"QueryPerformanceCounter",
                r"GetSystemTime", r"time\s*\("
            ],
            "sleep_operations": [
                r"Sleep\s*\(", r"SleepEx", r"WaitForSingleObject",
                r"delay\s*\(", r"pause\s*\("
            ],
            "anti_vm_checks": [
                r"GetSystemFirmwareTable", r"EnumSystemFirmwareTables",
                r"GetSystemInfo", r"GetComputerName",
                r"GetUserName", r"GetVolumeInformation"
            ]
        }
        
        evasion_score = 0
        detected_evasion = []
        for evasion_type, patterns in evasion_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    evasion_score += 12
                    detected_evasion.append(evasion_type)
                    break
        
        if evasion_score > 0:
            behavior_results["behaviors"].append("evasion_techniques")
            behavior_results["score"] += evasion_score
            behavior_results["details"]["evasion_methods"] = detected_evasion
        
        # 5. File System Operations
        file_ops_patterns = {
            "file_creation": [
                r"CreateFile", r"CreateFileW", r"CreateFileA",
                r"fopen", r"open\s*\("
            ],
            "file_writing": [
                r"WriteFile", r"fwrite", r"write\s*\(",
                r"SetFilePointer", r"SetEndOfFile"
            ],
            "file_deletion": [
                r"DeleteFile", r"DeleteFileW", r"DeleteFileA",
                r"remove\s*\(", r"unlink\s*\("
            ],
            "file_attributes": [
                r"SetFileAttributes", r"GetFileAttributes",
                r"SetFileTime", r"GetFileTime"
            ]
        }
        
        file_ops_score = 0
        detected_file_ops = []
        for op_type, patterns in file_ops_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    file_ops_score += 5
                    detected_file_ops.append(op_type)
                    break
        
        if file_ops_score > 0:
            behavior_results["behaviors"].append("file_operations")
            behavior_results["score"] += file_ops_score
            behavior_results["details"]["file_operations"] = detected_file_ops
        
        # 6. Privilege Escalation Detection
        privilege_patterns = {
            "uac_bypass": [
                r"UAC", r"User Account Control", r"elevate",
                r"runas", r"ShellExecute.*runas"
            ],
            "token_manipulation": [
                r"OpenProcessToken", r"DuplicateTokenEx",
                r"ImpersonateLoggedOnUser", r"SetThreadToken"
            ],
            "service_privileges": [
                r"SeDebugPrivilege", r"SeTcbPrivilege",
                r"SeBackupPrivilege", r"SeRestorePrivilege"
            ]
        }
        
        privilege_score = 0
        detected_privilege = []
        for priv_type, patterns in privilege_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    privilege_score += 20
                    detected_privilege.append(priv_type)
                    break
        
        if privilege_score > 0:
            behavior_results["behaviors"].append("privilege_escalation")
            behavior_results["score"] += privilege_score
            behavior_results["details"]["privilege_methods"] = detected_privilege
        
        # 7. Memory Manipulation
        memory_patterns = {
            "memory_allocation": [
                r"VirtualAlloc", r"VirtualAllocEx", r"HeapAlloc",
                r"malloc", r"calloc", r"new\s*\["
            ],
            "memory_protection": [
                r"VirtualProtect", r"VirtualProtectEx",
                r"PAGE_EXECUTE_READWRITE", r"PAGE_EXECUTE_READ"
            ],
            "memory_mapping": [
                r"CreateFileMapping", r"MapViewOfFile",
                r"MapViewOfFileEx", r"mmap"
            ]
        }
        
        memory_score = 0
        detected_memory = []
        for mem_type, patterns in memory_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    memory_score += 8
                    detected_memory.append(mem_type)
                    break
        
        if memory_score > 0:
            behavior_results["behaviors"].append("memory_manipulation")
            behavior_results["score"] += memory_score
            behavior_results["details"]["memory_operations"] = detected_memory
        
        # Calculate confidence and risk level
        behavior_results["confidence"] = min(95, behavior_results["score"] + 30)
        
        if behavior_results["score"] >= 80:
            behavior_results["risk_level"] = "critical"
        elif behavior_results["score"] >= 60:
            behavior_results["risk_level"] = "high"
        elif behavior_results["score"] >= 40:
            behavior_results["risk_level"] = "medium"
        elif behavior_results["score"] >= 20:
            behavior_results["risk_level"] = "low"
        else:
            behavior_results["risk_level"] = "minimal"
        
        return behavior_results
        
    except Exception as e:
        return {
            "score": 0,
            "behaviors": [],
            "confidence": 0,
            "risk_level": "unknown",
            "details": {"error": str(e)}
        }

def analyze_behavioral_context(file_path: str, behavior_results: Dict) -> Dict:
    """Analyze behavioral context to reduce false positives"""
    try:
        context_adjustment = 0
        context_factors = []
        
        # Check if file is in trusted locations
        file_path_lower = file_path.lower()
        trusted_locations = [
            "system32", "syswow64", "program files", "windows",
            "microsoft", "adobe", "oracle", "intel", "amd"
        ]
        
        if any(loc in file_path_lower for loc in trusted_locations):
            context_adjustment -= 20
            context_factors.append("trusted_location")
        
        # Check file age
        try:
            file_age = time.time() - os.path.getctime(file_path)
            if file_age < 3600:  # Less than 1 hour
                context_adjustment += 15
                context_factors.append("recent_file")
            elif file_age < 86400:  # Less than 1 day
                context_adjustment += 8
                context_factors.append("new_file")
        except Exception:
            pass
        
        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 1024:  # Very small file
                context_adjustment += 10
                context_factors.append("small_file")
            elif file_size > 50 * 1024 * 1024:  # Very large file
                context_adjustment += 5
                context_factors.append("large_file")
        except Exception:
            pass
        
        # Check for legitimate software indicators
        legitimate_indicators = [
            "microsoft", "adobe", "oracle", "intel", "amd", "nvidia",
            "chrome", "firefox", "edge", "office", "visual studio"
        ]
        
        if any(indicator in file_path_lower for indicator in legitimate_indicators):
            context_adjustment -= 15
            context_factors.append("legitimate_software")
        
        # Apply context adjustment
        adjusted_score = max(0, behavior_results["score"] + context_adjustment)
        
        return {
            "original_score": behavior_results["score"],
            "adjusted_score": adjusted_score,
            "context_adjustment": context_adjustment,
            "context_factors": context_factors,
            "final_risk_level": "critical" if adjusted_score >= 80 else
                              "high" if adjusted_score >= 60 else
                              "medium" if adjusted_score >= 40 else
                              "low" if adjusted_score >= 20 else "minimal"
        }
        
    except Exception as e:
        return {
            "original_score": behavior_results["score"],
            "adjusted_score": behavior_results["score"],
            "context_adjustment": 0,
            "context_factors": ["error"],
            "final_risk_level": behavior_results["risk_level"]
        } 

# Initialize enterprise YARA engine
if ENTERPRISE_YARA_AVAILABLE:
    try:
        enterprise_yara_engine = EnterpriseYaraEngine()
        print("Enterprise YARA engine initialized successfully")
    except Exception as e:
        print(f"Failed to initialize enterprise YARA engine: {e}")
        enterprise_yara_engine = None
else:
    enterprise_yara_engine = None

def scan_file(file_path):
    """Enhanced file scanning with enterprise YARA capabilities"""
    if not file_path or not os.path.exists(file_path):
        return {'score': 0, 'reason': 'File not found', 'all_results': []}
    
    results = []
    file_hash = None
    
    try:
        # Calculate file hash
        with open(file_path, 'rb') as f:
            content = f.read()
            file_hash = hashlib.sha256(content).hexdigest()
        
        # 1. Enterprise YARA signature match (if available)
        if enterprise_yara_engine:
            try:
                yara_results = enterprise_yara_engine.scan_file(file_path)
                for result in yara_results:
                    results.append(('Enterprise_YARA', result.score, f"{result.rule_name}: {result.rule_description}"))
                    if result.score >= 80:  # High confidence enterprise detection
                        return {
                            'score': result.score, 
                            'reason': f"Enterprise YARA: {result.rule_name} - {result.rule_description}",
                            'all_results': results,
                            'family': result.family,
                            'technique': result.technique,
                            'mitre_attck': result.mitre_attck,
                            'confidence': result.confidence
                        }
            except Exception as e:
                logging.error(f"Enterprise YARA scan error: {str(e)}")
        
        # 2. Basic YARA signature match (fallback)
        try:
            yara_dir = "signatures"
            if os.path.exists(yara_dir):
                yara_files = [f for f in os.listdir(yara_dir) if f.endswith('.yar')]
                if yara_files:
                    yara_rules = yara.compile(filepath=os.path.join(yara_dir, yara_files[0]))
                    yara_matches = yara_rules.match(file_path)
                    if yara_matches:
                        results.append(('Basic_YARA', 85, str(yara_matches)))
        except Exception as e:
            logging.error(f"Basic YARA scan error: {str(e)}")
        
        # 3. Enhanced heuristic analysis
        heuristic_score = perform_enhanced_heuristic_analysis(file_path, content)
        if heuristic_score > 0:
            results.append(('Enhanced_Heuristic', heuristic_score, 'Advanced heuristic analysis'))
        
        # 4. Behavioral analysis (if executable)
        if is_executable(file_path):
            behavior_score = perform_behavioral_analysis(file_path)
            if behavior_score > 0:
                results.append(('Behavioral_Analysis', behavior_score, 'Behavioral analysis'))
        
        # 5. Threat intelligence integration
        if file_hash:
            ti_score = check_enhanced_threat_intelligence(file_hash)
            if ti_score > 0:
                results.append(('Threat_Intelligence', ti_score, 'Known malicious hash'))
        
        # 6. File type specific analysis
        file_type_score = perform_file_type_analysis(file_path, content)
        if file_type_score > 0:
            results.append(('File_Type_Analysis', file_type_score, 'File type specific detection'))
        
        # 7. Combine results with advanced scoring
        if results:
            final_score = calculate_advanced_score(results)
            top_result = max(results, key=lambda x: x[1])
            return {
                'score': final_score,
                'reason': top_result[2],
                'all_results': results,
                'file_hash': file_hash,
                'scan_timestamp': datetime.now().isoformat()
            }
        else:
            return {'score': 0, 'reason': 'Clean', 'all_results': [], 'file_hash': file_hash}
            
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {str(e)}")
        return {'score': 0, 'reason': f'Scan error: {str(e)}', 'all_results': []}

def perform_enhanced_heuristic_analysis(file_path, content):
    """Enhanced heuristic analysis with multiple detection techniques"""
    score = 0
    
    try:
        # Entropy analysis
        entropy = calculate_entropy(content)
        if entropy > 7.5:  # High entropy indicates possible encryption/packing
            score += 20
        
        # String analysis
        strings = extract_strings(content)
        suspicious_strings = [
            'cmd.exe', 'powershell', 'exec', 'eval', 'download', 'upload',
            'http://', 'https://', 'system32', 'registry', 'administrator',
            'service', 'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'
        ]
        
        suspicious_count = sum(1 for s in suspicious_strings if any(s.lower() in string.lower() for string in strings))
        if suspicious_count >= 3:
            score += 30
        
        # PE file analysis
        if is_pe_file(file_path):
            pe_score = analyze_pe_file(file_path)
            score += pe_score
        
        # Obfuscation detection
        if detect_obfuscation(content):
            score += 25
        
        # Network indicators
        if detect_network_indicators(content):
            score += 20
        
        return min(100, score)
        
    except Exception as e:
        logging.error(f"Enhanced heuristic analysis error: {str(e)}")
        return 0

def perform_file_type_analysis(file_path, content):
    """File type specific analysis"""
    score = 0
    file_extension = os.path.splitext(file_path)[1].lower()
    
    try:
        if file_extension in ['.pdf']:
            # PDF analysis
            if b'/JS' in content or b'/Launch' in content or b'/Action' in content:
                score += 40
            if b'base64' in content and len(content) > 10000:
                score += 20
                
        elif file_extension in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            # Office document analysis
            if b'VBA' in content or b'AutoOpen' in content or b'Shell.Application' in content:
                score += 50
            if b'powershell' in content or b'cmd.exe' in content:
                score += 30
                
        elif file_extension in ['.js', '.vbs', '.ps1']:
            # Script analysis
            if b'eval(' in content or b'unescape(' in content:
                score += 30
            if b'powershell' in content and b'-enc' in content:
                score += 40
            if b'http://' in content or b'https://' in content:
                score += 20
                
        elif file_extension in ['.exe', '.dll', '.sys']:
            # Executable analysis
            if b'VirtualAlloc' in content or b'WriteProcessMemory' in content:
                score += 25
            if b'cmd.exe' in content or b'powershell' in content:
                score += 30
                
        return score
        
    except Exception as e:
        logging.error(f"File type analysis error: {str(e)}")
        return 0

def calculate_advanced_score(results):
    """Calculate advanced score with weighted components"""
    if not results:
        return 0
    
    # Weight different detection methods
    weights = {
        'Enterprise_YARA': 1.0,
        'Basic_YARA': 0.8,
        'Enhanced_Heuristic': 0.7,
        'Behavioral_Analysis': 0.9,
        'Threat_Intelligence': 1.0,
        'File_Type_Analysis': 0.6
    }
    
    weighted_scores = []
    for method, score, reason in results:
        weight = weights.get(method, 0.5)
        weighted_scores.append(score * weight)
    
    # Use the highest weighted score as base
    base_score = max(weighted_scores)
    
    # Apply bonus for multiple detections
    detection_count = len(results)
    if detection_count >= 3:
        base_score = min(100, base_score + 10)
    elif detection_count >= 2:
        base_score = min(100, base_score + 5)
    
    return int(base_score) 

def determine_file_risk(extension: str, threat_score: int) -> tuple:
    """Determine file type and risk level based on extension and threat score"""
    # File type classification
    if extension in ['.exe', '.dll', '.sys', '.drv']:
        file_type = "Executable"
    elif extension in ['.js', '.vbs', '.ps1', '.bat', '.cmd']:
        file_type = "Script"
    elif extension in ['.zip', '.rar', '.7z', '.tar', '.gz']:
        file_type = "Archive"
    elif extension in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
        file_type = "Office Document"
    elif extension in ['.pdf']:
        file_type = "PDF"
    elif extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg']:
        file_type = "Image"
    elif extension in ['.mp3', '.mp4', '.avi', '.mov', '.wav', '.flv', '.mkv']:
        file_type = "Media"
    elif extension in ['.txt', '.log', '.ini', '.cfg', '.xml', '.json']:
        file_type = "Text"
    else:
        file_type = "Unknown"
    
    # Risk level determination
    if threat_score >= 90 or (file_type == "Executable" and threat_score >= 70):
        risk_level = "Critical"
    elif threat_score >= 80 or (file_type in ["Script", "Archive"] and threat_score >= 60):
        risk_level = "High"
    elif threat_score >= 60 or (file_type in ["Office Document", "PDF"] and threat_score >= 50):
        risk_level = "Medium"
    elif threat_score >= 40:
        risk_level = "Low"
    else:
        risk_level = "Minimal"
    
    return file_type, risk_level

def determine_alert_severity(threat_score: int, risk_level: str) -> AlertSeverity:
    """Determine alert severity based on threat score and risk level"""
    if threat_score >= 90 or risk_level == "Critical":
        return AlertSeverity.CRITICAL
    elif threat_score >= 80 or risk_level == "High":
        return AlertSeverity.HIGH
    elif threat_score >= 60 or risk_level == "Medium":
        return AlertSeverity.MEDIUM
    else:
        return AlertSeverity.LOW

def create_alert(severity: AlertSeverity, title: str, message: str, file_info: Dict = None):
    """Create a new alert and notify connected clients"""
    alert = {
        "id": f"alert_{int(time.time())}",
        "severity": severity.value,
        "title": title,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "file_info": file_info,
        "acknowledged": False
    }
    
    active_alerts.append(alert)
    
    # Keep only last 100 alerts
    if len(active_alerts) > 100:
        active_alerts.pop(0)
    
    # Notify connected clients (only if we're in an async context)
    try:
        asyncio.create_task(notify_clients(alert))
    except RuntimeError:
        # If no event loop is running, just skip the notification
        pass
    
    return alert

async def notify_clients(alert):
    """Notify all connected WebSocket clients about new alerts"""
    if not QUARANTINE_CONFIG["enable_notifications"]:
        return
    
    message = {
        "type": "alert",
        "data": alert
    }
    
    for client in connected_clients[:]:  # Copy list to avoid modification during iteration
        try:
            await client.send_text(json.dumps(message))
        except:
            connected_clients.remove(client)

# New endpoints for enhanced quarantine management
@app.get("/api/alerts")
def get_alerts():
    """Get all active alerts"""
    return {
        "alerts": active_alerts,
        "unacknowledged_count": len([a for a in active_alerts if not a["acknowledged"]])
    }

@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    """Mark an alert as acknowledged"""
    for alert in active_alerts:
        if alert["id"] == alert_id:
            alert["acknowledged"] = True
            return {"message": "Alert acknowledged"}
    
    return JSONResponse(
        status_code=404,
        content={"detail": "Alert not found"}
    )

@app.delete("/api/alerts/{alert_id}")
def delete_alert(alert_id: str):
    """Delete an alert"""
    global active_alerts
    active_alerts = [a for a in active_alerts if a["id"] != alert_id]
    return {"message": "Alert deleted"} 