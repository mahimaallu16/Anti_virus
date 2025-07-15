#!/usr/bin/env python3
"""
Enterprise YARA Test Script
============================
Demonstrates the advanced YARA capabilities and features
"""

import os
import sys
import json
import time
from datetime import datetime

def test_enterprise_yara():
    """Test the enterprise YARA engine capabilities"""
    
    print("Enterprise YARA Engine Test")
    print("=" * 40)
    
    # Test enterprise YARA engine availability
    try:
        from enterprise_yara_engine import EnterpriseYaraEngine
        print("✓ Enterprise YARA engine imported successfully")
        
        # Initialize engine
        engine = EnterpriseYaraEngine()
        print("✓ Enterprise YARA engine initialized")
        
        # Get statistics
        stats = engine.get_rule_statistics()
        print(f"✓ Loaded {stats['total_rules']} rules")
        print(f"✓ Compiled {stats['compiled_rules']} rules")
        
        # Test rule categories
        print("\nRule Categories:")
        for category, count in stats['categories'].items():
            print(f"  - {category}: {count} rules")
        
        # Test file scanning (if test file exists)
        test_file = "test_file.exe"
        if os.path.exists(test_file):
            print(f"\nTesting scan on {test_file}")
            results = engine.scan_file(test_file)
            if results:
                print(f"✓ Scan completed: {len(results)} results")
                for result in results:
                    print(f"  - {result.rule_name}: {result.score}/100")
            else:
                print("✓ Scan completed: No threats detected")
        
        # Test directory scanning
        test_dir = "uploads"
        if os.path.exists(test_dir):
            print(f"\nTesting directory scan on {test_dir}")
            dir_results = engine.scan_directory(test_dir)
            if dir_results:
                print(f"✓ Directory scan completed: {len(dir_results)} files with results")
            else:
                print("✓ Directory scan completed: No threats detected")
        
        print("\n✓ All enterprise YARA tests passed!")
        return True
        
    except ImportError as e:
        print(f"✗ Enterprise YARA engine not available: {e}")
        return False
    except Exception as e:
        print(f"✗ Enterprise YARA test failed: {e}")
        return False

def test_configuration():
    """Test enterprise YARA configuration"""
    
    print("\nConfiguration Test")
    print("=" * 20)
    
    config_file = "enterprise_yara_config.json"
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            print("✓ Configuration file loaded")
            
            # Test configuration sections
            sections = ['general', 'rule_categories', 'scoring', 'threat_intelligence']
            for section in sections:
                if section in config.get('enterprise_yara', {}):
                    print(f"✓ {section} configuration present")
                else:
                    print(f"✗ {section} configuration missing")
            
            return True
            
        except Exception as e:
            print(f"✗ Configuration test failed: {e}")
            return False
    else:
        print("✗ Configuration file not found")
        return False

def test_yara_rules():
    """Test YARA rule files"""
    
    print("\nYARA Rules Test")
    print("=" * 15)
    
    rule_files = [
        "signatures/enterprise_rules.yar",
        "signatures/advanced_malware_families.yar",
        "signatures/advanced_attack_techniques.yar"
    ]
    
    all_present = True
    for rule_file in rule_files:
        if os.path.exists(rule_file):
            print(f"✓ {rule_file} present")
        else:
            print(f"✗ {rule_file} missing")
            all_present = False
    
    return all_present

def main():
    """Main test function"""
    
    print("Enterprise YARA System Test")
    print("=" * 30)
    print(f"Test started at: {datetime.now()}")
    
    # Run tests
    tests = [
        ("Enterprise YARA Engine", test_enterprise_yara),
        ("Configuration", test_configuration),
        ("YARA Rules", test_yara_rules)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\nRunning {test_name} test...")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ {test_name} test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 30)
    print("Test Summary")
    print("=" * 30)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! Enterprise YARA system is ready.")
    else:
        print("✗ Some tests failed. Please check the configuration.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 