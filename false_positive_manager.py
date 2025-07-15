import json
import os
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional

class FalsePositiveManager:
    def __init__(self, config_file: str = "false_positive_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.whitelist_cache = set()
        self.false_positive_history = []
        self.user_feedback = {}
        
    def load_config(self) -> Dict:
        """Load false positive reduction configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
        
        # Return default configuration
        return {
            "false_positive_reduction": {
                "enabled": True,
                "whitelist": {"enabled": True, "paths": [], "extensions": []},
                "digital_signature": {"enabled": True, "trust_signed_files": True},
                "context_analysis": {"enabled": True},
                "heuristic_thresholds": {"min_total_score": 60, "min_indicators": 2}
            }
        }
    
    def save_config(self):
        """Save current configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def is_whitelisted(self, file_path: str, file_hash: str = None) -> bool:
        """Check if file is whitelisted"""
        if not self.config["false_positive_reduction"]["whitelist"]["enabled"]:
            return False
        
        # Check cache first
        if file_path in self.whitelist_cache:
            return True
        
        # Check hash-based whitelist
        if file_hash and file_hash in self.get_safe_hashes():
            return True
        
        # Check path-based whitelist
        file_path_lower = file_path.lower()
        for whitelisted_path in self.config["false_positive_reduction"]["whitelist"]["paths"]:
            if file_path_lower.startswith(whitelisted_path.lower()):
                self.whitelist_cache.add(file_path)
                return True
        
        # Check extension-based whitelist
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in self.config["false_positive_reduction"]["whitelist"]["extensions"]:
            self.whitelist_cache.add(file_path)
            return True
        
        return False
    
    def get_safe_hashes(self) -> Set[str]:
        """Get set of known safe file hashes"""
        safe_hashes_file = "safe_hashes.json"
        try:
            if os.path.exists(safe_hashes_file):
                with open(safe_hashes_file, 'r') as f:
                    return set(json.load(f))
        except Exception:
            pass
        return set()
    
    def add_safe_hash(self, file_hash: str):
        """Add a file hash to the safe hashes list"""
        safe_hashes = self.get_safe_hashes()
        safe_hashes.add(file_hash)
        
        try:
            with open("safe_hashes.json", 'w') as f:
                json.dump(list(safe_hashes), f)
        except Exception as e:
            print(f"Error saving safe hash: {e}")
    
    def analyze_context(self, file_path: str) -> Dict:
        """Analyze file context for false positive reduction"""
        context = {
            "score": 0,
            "factors": [],
            "trusted_location": False
        }
        
        try:
            file_path_lower = file_path.lower()
            
            # Check if in trusted system directories
            system_dirs = ["system32", "syswow64", "program files", "windows"]
            if any(dir_name in file_path_lower for dir_name in system_dirs):
                context["trusted_location"] = True
                context["score"] -= 30
                context["factors"].append("trusted_system_location")
            
            # Check file age
            try:
                file_age = time.time() - os.path.getctime(file_path)
                if file_age < 3600:  # Less than 1 hour
                    context["score"] += 20
                    context["factors"].append("recent_file")
                elif file_age < 86400:  # Less than 1 day
                    context["score"] += 10
                    context["factors"].append("new_file")
            except Exception:
                pass
            
            # Check file size
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 1024 and file_path_lower.endswith('.exe'):
                    context["score"] += 25
                    context["factors"].append("small_executable")
            except Exception:
                pass
            
            # Check location
            suspicious_locations = ["temp", "tmp", "downloads", "desktop"]
            if any(loc in file_path_lower for loc in suspicious_locations):
                context["score"] += 15
                context["factors"].append("suspicious_location")
            
        except Exception as e:
            print(f"Error analyzing context: {e}")
        
        return context
    
    def should_quarantine(self, threat_score: int, file_path: str, context: Dict) -> bool:
        """Determine if file should be quarantined based on score and context"""
        threshold = self.config["quarantine"]["threshold"]
        
        # Reduce score for trusted locations
        if context.get("trusted_location", False):
            threat_score = max(0, threat_score - 30)
        
        # Check if score meets quarantine threshold
        return threat_score >= threshold
    
    def record_false_positive(self, file_path: str, threat_type: str, user_action: str):
        """Record false positive for learning"""
        false_positive = {
            "file_path": file_path,
            "threat_type": threat_type,
            "user_action": user_action,  # "restored", "ignored", "quarantined"
            "timestamp": datetime.now().isoformat(),
            "file_hash": self.get_file_hash(file_path)
        }
        
        self.false_positive_history.append(false_positive)
        
        # If user restored the file, add to safe hashes
        if user_action == "restored":
            file_hash = self.get_file_hash(file_path)
            if file_hash:
                self.add_safe_hash(file_hash)
        
        # Save false positive history
        self.save_false_positive_history()
    
    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Get SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None
    
    def save_false_positive_history(self):
        """Save false positive history to file"""
        try:
            with open("false_positive_history.json", 'w') as f:
                json.dump(self.false_positive_history, f, indent=2)
        except Exception as e:
            print(f"Error saving false positive history: {e}")
    
    def load_false_positive_history(self):
        """Load false positive history from file"""
        try:
            if os.path.exists("false_positive_history.json"):
                with open("false_positive_history.json", 'r') as f:
                    self.false_positive_history = json.load(f)
        except Exception as e:
            print(f"Error loading false positive history: {e}")
    
    def get_false_positive_stats(self) -> Dict:
        """Get statistics about false positives"""
        stats = {
            "total_false_positives": len(self.false_positive_history),
            "by_threat_type": {},
            "by_user_action": {},
            "recent_false_positives": 0
        }
        
        # Count by threat type and user action
        for fp in self.false_positive_history:
            threat_type = fp.get("threat_type", "unknown")
            user_action = fp.get("user_action", "unknown")
            
            stats["by_threat_type"][threat_type] = stats["by_threat_type"].get(threat_type, 0) + 1
            stats["by_user_action"][user_action] = stats["by_user_action"].get(user_action, 0) + 1
            
            # Count recent false positives (last 7 days)
            try:
                fp_time = datetime.fromisoformat(fp["timestamp"])
                if fp_time > datetime.now() - timedelta(days=7):
                    stats["recent_false_positives"] += 1
            except Exception:
                pass
        
        return stats
    
    def optimize_thresholds(self):
        """Automatically optimize detection thresholds based on false positive history"""
        if len(self.false_positive_history) < 10:
            return  # Need more data
        
        # Analyze false positive patterns
        high_fp_threat_types = []
        for threat_type, count in self.get_false_positive_stats()["by_threat_type"].items():
            if count > 5:  # More than 5 false positives for this type
                high_fp_threat_types.append(threat_type)
        
        # Adjust thresholds for high false positive threat types
        for threat_type in high_fp_threat_types:
            if threat_type == "heuristic":
                # Increase heuristic threshold
                current_threshold = self.config["false_positive_reduction"]["heuristic_thresholds"]["min_total_score"]
                self.config["false_positive_reduction"]["heuristic_thresholds"]["min_total_score"] = min(80, current_threshold + 10)
            elif threat_type == "behavior":
                # Increase behavior threshold
                current_threshold = self.config["quarantine"]["threshold"]
                self.config["quarantine"]["threshold"] = min(90, current_threshold + 5)
        
        self.save_config()
    
    def generate_report(self) -> str:
        """Generate a false positive reduction report"""
        stats = self.get_false_positive_stats()
        
        report = f"""
False Positive Reduction Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary:
- Total False Positives: {stats['total_false_positives']}
- Recent False Positives (7 days): {stats['recent_false_positives']}
- Safe Hashes in Database: {len(self.get_safe_hashes())}

False Positives by Threat Type:
"""
        
        for threat_type, count in stats["by_threat_type"].items():
            report += f"- {threat_type}: {count}\n"
        
        report += "\nUser Actions:\n"
        for action, count in stats["by_user_action"].items():
            report += f"- {action}: {count}\n"
        
        return report

# Global instance
fp_manager = FalsePositiveManager() 