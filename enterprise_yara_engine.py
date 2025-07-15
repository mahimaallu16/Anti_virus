"""
Enterprise-Grade YARA Engine for Advanced Malware Detection
==========================================================
This module provides enterprise-level YARA capabilities including:
- Advanced rule categorization and management
- Dynamic rule compilation and caching
- Threat intelligence integration
- Machine learning scoring
- Rule versioning and updates
- Performance optimization
"""

import os
import json
import time
import yara
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from functools import lru_cache
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import pickle
import gzip

@dataclass
class YaraRule:
    """Represents a YARA rule with metadata"""
    name: str
    description: str
    severity: str
    family: Optional[str]
    technique: Optional[str]
    mitre_attck: Optional[str]
    confidence: str
    version: str
    author: str
    date: str
    tags: List[str]
    rule_content: str
    compiled_rule: Optional[yara.Rule] = None
    last_updated: Optional[datetime] = None

@dataclass
class ScanResult:
    """Represents a YARA scan result"""
    rule_name: str
    rule_description: str
    severity: str
    confidence: str
    family: Optional[str]
    technique: Optional[str]
    mitre_attck: Optional[str]
    matched_strings: List[str]
    score: int
    timestamp: datetime
    file_path: str
    file_hash: str

class EnterpriseYaraEngine:
    """Enterprise-grade YARA engine with advanced features"""
    
    def __init__(self, rules_directory: str = "signatures", cache_directory: str = "cache"):
        self.rules_directory = rules_directory
        self.cache_directory = cache_directory
        self.rules: Dict[str, YaraRule] = {}
        self.compiled_rules: Dict[str, yara.Rule] = {}
        self.rule_categories = {
            'malware_families': [],
            'attack_techniques': [],
            'file_types': [],
            'evasion': [],
            'network': [],
            'persistence': [],
            'privilege_escalation': [],
            'ransomware': [],
            'cryptominer': [],
            'generic': []
        }
        self.threat_intelligence = {}
        self.ml_scoring_model = None
        self.rule_cache = {}
        self.last_update = None
        self.update_interval = 3600  # 1 hour
        self.max_workers = 4
        
        # Initialize directories
        os.makedirs(self.rules_directory, exist_ok=True)
        os.makedirs(self.cache_directory, exist_ok=True)
        
        # Initialize logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Load rules
        self.load_all_rules()
        self.compile_rules()
        
    def load_all_rules(self) -> None:
        """Load all YARA rules from the rules directory, including web threat rules"""
        try:
            yara_files = [f for f in os.listdir(self.rules_directory) if f.endswith('.yar')]
            # MAINTAINERS: Add new YARA rules for web threats (JavaScript, phishing, drive-by downloads) to the signatures directory.
            for yara_file in yara_files:
                file_path = os.path.join(self.rules_directory, yara_file)
                self.load_rules_from_file(file_path)
            self.logger.info(f"Loaded {len(self.rules)} YARA rules (including web threat rules)")
            self.categorize_rules()
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {str(e)}")
    
    def load_rules_from_file(self, file_path: str) -> None:
        """Load YARA rules from a specific file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse rules using YARA
            rules = yara.compile(source=content)
            
            # Extract rule information
            for rule in rules:
                rule_info = self.extract_rule_metadata(rule, content)
                if rule_info:
                    self.rules[rule.name] = rule_info
                    
        except Exception as e:
            self.logger.error(f"Error loading rules from {file_path}: {str(e)}")
    
    def extract_rule_metadata(self, rule: yara.Rule, content: str) -> Optional[YaraRule]:
        """Extract metadata from a YARA rule"""
        try:
            # Find the rule in the content
            rule_start = content.find(f"rule {rule.name}")
            if rule_start == -1:
                return None
            
            # Extract the rule content
            rule_end = content.find("}", rule_start)
            if rule_end == -1:
                return None
            
            rule_content = content[rule_start:rule_end + 1]
            
            # Extract metadata from meta section
            meta_start = rule_content.find("meta:")
            meta_end = rule_content.find("strings:", meta_start)
            
            metadata = {}
            if meta_start != -1 and meta_end != -1:
                meta_section = rule_content[meta_start:meta_end]
                for line in meta_section.split('\n'):
                    line = line.strip()
                    if '=' in line and not line.startswith('meta:'):
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        metadata[key] = value
            
            return YaraRule(
                name=rule.name,
                description=metadata.get('description', ''),
                severity=metadata.get('severity', 'Medium'),
                family=metadata.get('family'),
                technique=metadata.get('technique'),
                mitre_attck=metadata.get('mitre_attck'),
                confidence=metadata.get('confidence', 'Low'),
                version=metadata.get('version', '1.0'),
                author=metadata.get('author', 'Unknown'),
                date=metadata.get('date', ''),
                tags=metadata.get('tags', '').split(',') if metadata.get('tags') else [],
                rule_content=rule_content,
                compiled_rule=rule,
                last_updated=datetime.now()
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata from rule {rule.name}: {str(e)}")
            return None
    
    def categorize_rules(self) -> None:
        """Categorize rules based on their metadata"""
        for rule_name, rule in self.rules.items():
            if rule.family:
                self.rule_categories['malware_families'].append(rule_name)
            elif rule.technique:
                if 'persistence' in rule.technique.lower():
                    self.rule_categories['persistence'].append(rule_name)
                elif 'privilege' in rule.technique.lower():
                    self.rule_categories['privilege_escalation'].append(rule_name)
                elif 'injection' in rule.technique.lower():
                    self.rule_categories['attack_techniques'].append(rule_name)
                elif 'evasion' in rule.technique.lower() or 'anti' in rule.technique.lower():
                    self.rule_categories['evasion'].append(rule_name)
                else:
                    self.rule_categories['attack_techniques'].append(rule_name)
            elif 'network' in rule.description.lower() or 'c2' in rule.description.lower():
                self.rule_categories['network'].append(rule_name)
            elif 'ransomware' in rule.description.lower() or 'ransom' in rule.description.lower():
                self.rule_categories['ransomware'].append(rule_name)
            elif 'cryptominer' in rule.description.lower() or 'mining' in rule.description.lower():
                self.rule_categories['cryptominer'].append(rule_name)
            elif 'pdf' in rule.description.lower() or 'office' in rule.description.lower() or 'javascript' in rule.description.lower():
                self.rule_categories['file_types'].append(rule_name)
            else:
                self.rule_categories['generic'].append(rule_name)
    
    def compile_rules(self) -> None:
        """Compile all YARA rules for performance"""
        try:
            for rule_name, rule in self.rules.items():
                if rule.compiled_rule:
                    self.compiled_rules[rule_name] = rule.compiled_rule
            
            self.logger.info(f"Compiled {len(self.compiled_rules)} YARA rules")
            
        except Exception as e:
            self.logger.error(f"Error compiling YARA rules: {str(e)}")
    
    @lru_cache(maxsize=1000)
    def get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file with caching"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def scan_file(self, file_path: str, categories: Optional[List[str]] = None) -> List[ScanResult]:
        """Scan a file with YARA rules"""
        if not os.path.exists(file_path):
            return []
        
        results = []
        file_hash = self.get_file_hash(file_path)
        
        # Determine which rules to use
        rules_to_scan = self.compiled_rules
        if categories:
            rules_to_scan = {
                rule_name: rule for rule_name, rule in self.compiled_rules.items()
                if any(cat in self.rule_categories for cat in categories)
            }
        
        try:
            # Perform YARA scan
            matches = yara.match(file_path, rules=rules_to_scan.values())
            
            for match in matches:
                rule = self.rules.get(match.rule)
                if rule:
                    # Calculate score based on rule severity and confidence
                    score = self.calculate_score(rule, match)
                    
                    # Apply machine learning scoring if available
                    if self.ml_scoring_model:
                        ml_score = self.apply_ml_scoring(file_path, rule, match)
                        score = (score + ml_score) // 2
                    
                    # Apply threat intelligence scoring
                    ti_score = self.apply_threat_intelligence(file_hash, rule)
                    if ti_score > 0:
                        score = min(100, score + ti_score)
                    
                    result = ScanResult(
                        rule_name=rule.name,
                        rule_description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        family=rule.family,
                        technique=rule.technique,
                        mitre_attck=rule.mitre_attck,
                        matched_strings=[str(s) for s in match.strings],
                        score=score,
                        timestamp=datetime.now(),
                        file_path=file_path,
                        file_hash=file_hash
                    )
                    results.append(result)
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
        
        return results
    
    def calculate_score(self, rule: YaraRule, match: yara.Match) -> int:
        """Calculate detection score based on rule severity and match"""
        base_score = {
            'Critical': 90,
            'High': 80,
            'Medium': 60,
            'Low': 40
        }.get(rule.severity, 50)
        
        confidence_multiplier = {
            'High': 1.0,
            'Medium': 0.8,
            'Low': 0.6
        }.get(rule.confidence, 0.7)
        
        # Adjust score based on number of matched strings
        string_bonus = min(10, len(match.strings) * 2)
        
        return min(100, int(base_score * confidence_multiplier) + string_bonus)
    
    def apply_ml_scoring(self, file_path: str, rule: YaraRule, match: yara.Match) -> int:
        """Apply machine learning scoring (placeholder for future implementation)"""
        # This would integrate with a trained ML model
        # For now, return a basic score based on file characteristics
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # Files > 10MB
                return 20
            elif file_size > 1024 * 1024:  # Files > 1MB
                return 40
            else:
                return 60
        except:
            return 50
    
    def apply_threat_intelligence(self, file_hash: str, rule: YaraRule) -> int:
        """Apply threat intelligence scoring"""
        if not file_hash or file_hash not in self.threat_intelligence:
            return 0
        
        ti_data = self.threat_intelligence[file_hash]
        
        # Check if hash is known malicious
        if ti_data.get('malicious', False):
            return 20
        
        # Check reputation score
        reputation = ti_data.get('reputation', 0)
        if reputation < 0:
            return abs(reputation)
        
        return 0
    
    def scan_directory(self, directory_path: str, categories: Optional[List[str]] = None) -> Dict[str, List[ScanResult]]:
        """Scan an entire directory with parallel processing"""
        results = {}
        
        # Get all files to scan
        files_to_scan = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                files_to_scan.append(file_path)
        
        # Scan files in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self.scan_file, file_path, categories): file_path
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_results = future.result()
                    if file_results:
                        results[file_path] = file_results
                except Exception as e:
                    self.logger.error(f"Error scanning {file_path}: {str(e)}")
        
        return results
    
    def update_threat_intelligence(self) -> None:
        """Update threat intelligence from external sources"""
        try:
            # Example threat intelligence sources
            sources = [
                "https://api.virustotal.com/v3/files/",
                "https://api.abuseipdb.com/api/v2/",
                "https://api.threatfox.abuse.ch/api/v1/"
            ]
            
            # This would integrate with actual threat intelligence APIs
            # For now, we'll create a mock update
            self.threat_intelligence = {
                # Mock data - in real implementation, this would come from APIs
                "mock_hash_1": {"malicious": True, "reputation": -50},
                "mock_hash_2": {"malicious": False, "reputation": -10}
            }
            
            self.logger.info("Threat intelligence updated")
            
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence: {str(e)}")
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded rules"""
        stats = {
            'total_rules': len(self.rules),
            'compiled_rules': len(self.compiled_rules),
            'categories': {},
            'severity_distribution': {},
            'confidence_distribution': {},
            'families': set(),
            'techniques': set()
        }
        
        for rule in self.rules.values():
            # Category distribution
            for category, rules in self.rule_categories.items():
                if rule.name in rules:
                    stats['categories'][category] = stats['categories'].get(category, 0) + 1
            
            # Severity distribution
            stats['severity_distribution'][rule.severity] = stats['severity_distribution'].get(rule.severity, 0) + 1
            
            # Confidence distribution
            stats['confidence_distribution'][rule.confidence] = stats['confidence_distribution'].get(rule.confidence, 0) + 1
            
            # Families and techniques
            if rule.family:
                stats['families'].add(rule.family)
            if rule.technique:
                stats['techniques'].add(rule.technique)
        
        # Convert sets to lists for JSON serialization
        stats['families'] = list(stats['families'])
        stats['techniques'] = list(stats['techniques'])
        
        return stats
    
    def export_rules(self, output_file: str, format: str = 'json') -> None:
        """Export rules to various formats"""
        try:
            if format == 'json':
                with open(output_file, 'w') as f:
                    json.dump({
                        'rules': [
                            {
                                'name': rule.name,
                                'description': rule.description,
                                'severity': rule.severity,
                                'family': rule.family,
                                'technique': rule.technique,
                                'mitre_attck': rule.mitre_attck,
                                'confidence': rule.confidence,
                                'version': rule.version,
                                'author': rule.author,
                                'date': rule.date,
                                'tags': rule.tags
                            }
                            for rule in self.rules.values()
                        ],
                        'statistics': self.get_rule_statistics()
                    }, f, indent=2)
            
            elif format == 'yara':
                with open(output_file, 'w') as f:
                    for rule in self.rules.values():
                        f.write(rule.rule_content + '\n\n')
            
            self.logger.info(f"Rules exported to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting rules: {str(e)}")
    
    def add_custom_rule(self, rule_content: str) -> bool:
        """Add a custom YARA rule"""
        try:
            # Compile the rule to validate it
            compiled_rule = yara.compile(source=rule_content)
            
            # Extract rule name
            rule_name = None
            for line in rule_content.split('\n'):
                if line.strip().startswith('rule '):
                    rule_name = line.strip().split()[1].split('{')[0].strip()
                    break
            
            if not rule_name:
                raise ValueError("Could not extract rule name")
            
            # Create rule object
            rule = YaraRule(
                name=rule_name,
                description="Custom rule",
                severity="Medium",
                family=None,
                technique=None,
                mitre_attck=None,
                confidence="Medium",
                version="1.0",
                author="Custom",
                date=datetime.now().strftime("%Y-%m-%d"),
                tags=["custom"],
                rule_content=rule_content,
                compiled_rule=compiled_rule,
                last_updated=datetime.now()
            )
            
            self.rules[rule_name] = rule
            self.compiled_rules[rule_name] = compiled_rule
            
            self.logger.info(f"Added custom rule: {rule_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding custom rule: {str(e)}")
            return False
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a YARA rule"""
        try:
            if rule_name in self.rules:
                del self.rules[rule_name]
                if rule_name in self.compiled_rules:
                    del self.compiled_rules[rule_name]
                
                # Remove from categories
                for category in self.rule_categories.values():
                    if rule_name in category:
                        category.remove(rule_name)
                
                self.logger.info(f"Removed rule: {rule_name}")
                return True
            else:
                self.logger.warning(f"Rule not found: {rule_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error removing rule: {str(e)}")
            return False

# Example usage and testing
if __name__ == "__main__":
    # Initialize the enterprise YARA engine
    engine = EnterpriseYaraEngine()
    
    # Print statistics
    stats = engine.get_rule_statistics()
    print("YARA Engine Statistics:")
    print(json.dumps(stats, indent=2))
    
    # Example scan
    test_file = "test_file.exe"  # Replace with actual test file
    if os.path.exists(test_file):
        results = engine.scan_file(test_file)
        print(f"\nScan results for {test_file}:")
        for result in results:
            print(f"- {result.rule_name}: {result.score}/100 ({result.severity})") 