#!/usr/bin/env python3
"""
Simple test to demonstrate the quarantine system
"""

import os
from app import (
    create_alert,
    determine_file_risk,
    determine_alert_severity,
    AlertSeverity,
    load_quarantine_db
)

def test_quarantine_system():
    """Test the quarantine system with simple operations"""
    
    print("🧪 Simple Quarantine System Test")
    print("=" * 50)
    
    # Test 1: File Risk Assessment
    print("\n1. Testing File Risk Assessment:")
    print("-" * 40)
    
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
        
        print(f"   {description}:")
        print(f"     Extension: {extension}")
        print(f"     Score: {score}/100")
        print(f"     File Type: {file_type}")
        print(f"     Risk Level: {risk_level}")
        print(f"     Alert Severity: {severity.value}")
        print()
    
    # Test 2: Alert System
    print("\n2. Testing Alert System:")
    print("-" * 40)
    
    # Create test alerts
    test_alerts = [
        (AlertSeverity.CRITICAL, "🚨 Critical Threat Detected", "Malware.exe has been quarantined", {"filename": "malware.exe", "score": 95}),
        (AlertSeverity.HIGH, "⚠️ High Risk File", "Suspicious script detected", {"filename": "script.js", "score": 85}),
        (AlertSeverity.MEDIUM, "ℹ️ Medium Risk", "Suspicious document found", {"filename": "document.pdf", "score": 70}),
        (AlertSeverity.LOW, "✅ Low Risk", "Minor threat detected", {"filename": "file.txt", "score": 30})
    ]
    
    for severity, title, message, file_info in test_alerts:
        alert = create_alert(severity, title, message, file_info)
        print(f"   Created Alert: {alert['title']}")
        print(f"     Severity: {alert['severity']}")
        print(f"     Message: {alert['message']}")
        print(f"     ID: {alert['id']}")
        print()
    
    # Test 3: Check quarantine database
    print("\n3. Checking quarantine database:")
    print("-" * 40)
    
    quarantine_db = load_quarantine_db()
    print(f"   Total quarantined files: {len(quarantine_db)}")
    
    if quarantine_db:
        for i, record in enumerate(quarantine_db):
            print(f"   {i+1}. {record['filename']} - Score: {record['threat_score']} - Risk: {record['risk_level']}")
    else:
        print("   No files currently in quarantine")
    
    print("\n✅ Simple Quarantine System Test Completed!")
    print("\n📋 What was tested:")
    print("   • File risk assessment and classification")
    print("   • Alert system with severity levels")
    print("   • Quarantine database operations")
    
    print("\n🔍 To test actual file quarantine:")
    print("   • Upload a suspicious file through the web interface")
    print("   • Run a scan that detects threats")
    print("   • Check the Quarantine page for quarantined files")
    print("   • Review alerts in the Alerts section")

if __name__ == "__main__":
    test_quarantine_system() 