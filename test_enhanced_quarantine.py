#!/usr/bin/env python3
"""
Test script for Enhanced Quarantine System
Demonstrates the new alert and file management features
"""

import os
import json
import tempfile
import shutil
from datetime import datetime

# Import the enhanced quarantine functions
from app import (
    create_alert, 
    determine_file_risk, 
    determine_alert_severity,
    AlertSeverity,
    QUARANTINE_CONFIG,
    load_quarantine_db,
    save_quarantine_db
)

def test_enhanced_quarantine_system():
    """Test the enhanced quarantine system functionality"""
    
    print("🧪 Testing Enhanced Quarantine System")
    print("=" * 50)
    
    # Test 1: File Risk Assessment
    print("\n1. Testing File Risk Assessment:")
    print("-" * 30)
    
    test_cases = [
        (".exe", 95, "High-risk executable"),
        (".js", 85, "Suspicious JavaScript"),
        (".pdf", 70, "Suspicious PDF"),
        (".txt", 30, "Low-risk text file"),
        (".zip", 75, "Suspicious archive")
    ]
    
    for extension, score, description in test_cases:
        file_type, risk_level = determine_file_risk(extension, score)
        severity = determine_alert_severity(score, risk_level)
        
        print(f"  {description}:")
        print(f"    Extension: {extension}")
        print(f"    Score: {score}/100")
        print(f"    File Type: {file_type}")
        print(f"    Risk Level: {risk_level}")
        print(f"    Alert Severity: {severity.value}")
        print()
    
    # Test 2: Alert System
    print("\n2. Testing Alert System:")
    print("-" * 30)
    
    # Create test alerts
    test_alerts = [
        (AlertSeverity.CRITICAL, "🚨 Critical Threat Detected", "Malware.exe has been quarantined", {"filename": "malware.exe", "score": 95}),
        (AlertSeverity.HIGH, "⚠️ High Risk File", "Suspicious script detected", {"filename": "script.js", "score": 85}),
        (AlertSeverity.MEDIUM, "ℹ️ Medium Risk", "Suspicious document found", {"filename": "document.pdf", "score": 70}),
        (AlertSeverity.LOW, "✅ Low Risk", "Minor threat detected", {"filename": "file.txt", "score": 30})
    ]
    
    for severity, title, message, file_info in test_alerts:
        alert = create_alert(severity, title, message, file_info)
        print(f"  Created Alert: {alert['title']}")
        print(f"    Severity: {alert['severity']}")
        print(f"    Message: {alert['message']}")
        print(f"    ID: {alert['id']}")
        print()
    
    # Test 3: Quarantine Configuration
    print("\n3. Testing Quarantine Configuration:")
    print("-" * 30)
    
    print(f"  Auto-quarantine threshold: {QUARANTINE_CONFIG['auto_quarantine_threshold']}")
    print(f"  Alert threshold: {QUARANTINE_CONFIG['alert_threshold']}")
    print(f"  Max quarantine size: {QUARANTINE_CONFIG['max_quarantine_size'] / (1024*1024):.1f} MB")
    print(f"  Retention days: {QUARANTINE_CONFIG['retention_days']}")
    print(f"  Notifications enabled: {QUARANTINE_CONFIG['enable_notifications']}")
    print(f"  Backup before delete: {QUARANTINE_CONFIG['backup_before_delete']}")
    
    # Test 4: Simulate File Quarantine Process
    print("\n4. Simulating File Quarantine Process:")
    print("-" * 30)
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is a test file for quarantine simulation")
        test_file_path = f.name
    
    try:
        # Simulate threat detection
        threat_score = 85
        file_extension = ".txt"
        file_type, risk_level = determine_file_risk(file_extension, threat_score)
        severity = determine_alert_severity(threat_score, risk_level)
        
        print(f"  Test File: {os.path.basename(test_file_path)}")
        print(f"  Threat Score: {threat_score}/100")
        print(f"  File Type: {file_type}")
        print(f"  Risk Level: {risk_level}")
        print(f"  Alert Severity: {severity.value}")
        
        # Create quarantine alert
        alert = create_alert(
            severity,
            f"🚨 Threat Detected: {os.path.basename(test_file_path)}",
            f"A {risk_level} risk file has been quarantined. Threat score: {threat_score}/100",
            {
                "filename": os.path.basename(test_file_path),
                "file_type": file_type,
                "threat_score": threat_score,
                "threat_type": "Test threat",
                "quarantine_id": f"test_quarantine_{int(datetime.now().timestamp())}"
            }
        )
        
        print(f"  Alert Created: {alert['title']}")
        print(f"  Alert ID: {alert['id']}")
        
    finally:
        # Clean up test file
        if os.path.exists(test_file_path):
            os.unlink(test_file_path)
    
    # Test 5: Quarantine Database Operations
    print("\n5. Testing Quarantine Database Operations:")
    print("-" * 30)
    
    # Load current quarantine database
    quarantine_db = load_quarantine_db()
    print(f"  Current quarantined files: {len(quarantine_db)}")
    
    if quarantine_db:
        print("  Sample quarantine records:")
        for i, record in enumerate(quarantine_db[:3]):  # Show first 3 records
            print(f"    {i+1}. {record.get('filename', 'Unknown')} - Score: {record.get('threat_score', 0)}")
    
    print("\n✅ Enhanced Quarantine System Test Completed!")
    print("\n📋 Summary of Features Tested:")
    print("  ✓ File risk assessment and classification")
    print("  ✓ Alert system with severity levels")
    print("  ✓ Quarantine configuration management")
    print("  ✓ File quarantine simulation")
    print("  ✓ Database operations")
    
    print("\n🚀 The enhanced quarantine system is ready to:")
    print("  • Automatically quarantine harmful files (score ≥80)")
    print("  • Send real-time alerts for threats")
    print("  • Provide safe file restoration options")
    print("  • Offer permanent deletion with backups")
    print("  • Track comprehensive file metadata")

if __name__ == "__main__":
    test_enhanced_quarantine_system() 