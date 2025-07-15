# Antivirus Scoring System

## Overview
The antivirus application uses a multi-layered scoring system to evaluate file threats. Scores range from 0 (clean) to 100 (highly malicious).

## Scoring Scale

| Score Range | Threat Level | Description |
|-------------|--------------|-------------|
| 0 | Clean | No threats detected |
| 1-30 | Low | Suspicious behavior detected |
| 31-60 | Medium | Potential threat with moderate risk |
| 61-80 | High | Likely malicious with significant risk |
| 81-100 | Critical | Highly malicious with immediate risk |

## Detection Methods

### 1. Signature-Based Detection (YARA Rules)
**Score: 95** - Highest confidence detection

Uses YARA pattern matching to identify known malware signatures:

```yara
rule Suspicious_Executable {
    meta:
        description = "Detects suspicious executable patterns"
        severity = "High"
    strings:
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $exec = "exec" nocase
        $eval = "eval" nocase
    condition:
        2 of them
}
```

**Scoring Logic:**
- Matches YARA rule → Score: 95
- Multiple rule matches → Score: 95 (highest threat level)

### 2. Behavior-Based Detection
**Score: 80** - High confidence based on suspicious behavior

**Suspicious File Locations:**
- System directories (`system32`, `syswow64`)
- Temporary folders (`temp`, `tmp`)
- Download folders with executable files

**Scoring Logic:**
- File in suspicious location → Score: 80
- Multiple suspicious indicators → Score: 80

### 3. Location-Based Detection
**Score: 75** - Medium-high confidence

**Suspicious Locations:**
- Temporary directories
- Unusual system paths
- Recently downloaded executables

### 4. File Type Analysis
**Score: 60** - Medium confidence

**Suspicious File Types:**
- JavaScript files with suspicious content
- Executables in non-standard locations
- Compressed files with executable content

### 5. Pattern-Based Detection
**Score: 85** - High confidence for system-level threats

**System-Level Threats:**
- DLL files in system directories
- Registry modifications
- Service installations

## Scan Type Scoring Examples

### Quick Scan
```python
# Quick scan - check common locations
threats.append({
    "path": "C:/temp/suspicious.exe",
    "threat": "Suspicious executable in temp folder",
    "score": 75  # Location-based detection
})
```

### Full Scan
```python
# Full scan - comprehensive system check
threats.extend([
    {
        "path": "C:/Downloads/malware.zip",
        "threat": "Malware detected in downloads",
        "score": 90  # High confidence malware
    },
    {
        "path": "C:/Users/Desktop/suspicious.js",
        "threat": "Suspicious JavaScript file",
        "score": 60  # Medium confidence
    }
])
```

### System Scan
```python
# System scan - system directory focus
threats.append({
    "path": "C:/Windows/System32/suspicious.dll",
    "threat": "Suspicious DLL in system directory",
    "score": 85  # System-level threat
})
```

## Real-Time Scoring Algorithm

```python
def calculate_threat_score(file_path, file_content, file_metadata):
    score = 0
    
    # 1. YARA signature matching (95 points)
    if yara_rules.match(file_path):
        score = max(score, 95)
    
    # 2. Behavior analysis (80 points)
    if suspicious_location(file_path):
        score = max(score, 80)
    
    # 3. File type analysis (60 points)
    if suspicious_file_type(file_path):
        score = max(score, 60)
    
    # 4. Pattern analysis (85 points)
    if system_level_threat(file_path):
        score = max(score, 85)
    
    return min(score, 100)  # Cap at 100
```

## Threat Categories

### High-Risk Indicators (Score: 81-100)
- Known malware signatures
- System-level modifications
- Network communication patterns
- Administrative privilege escalation

### Medium-Risk Indicators (Score: 61-80)
- Suspicious file locations
- Unusual file types
- Behavioral anomalies
- Temporary file execution

### Low-Risk Indicators (Score: 31-60)
- Suspicious patterns
- Unusual file names
- Recent downloads
- Non-standard locations

### Clean Files (Score: 0-30)
- No suspicious indicators
- Standard file locations
- Known safe file types
- Verified digital signatures

## Response Actions

| Score Range | Action | Description |
|-------------|--------|-------------|
| 0-30 | Monitor | Log activity, no immediate action |
| 31-60 | Alert | Show warning, recommend scan |
| 61-80 | Quarantine | Isolate file, require user approval |
| 81-100 | Block | Immediate quarantine, high priority |

## Continuous Improvement

The scoring system is designed to:
- Learn from new threats
- Adapt to emerging patterns
- Reduce false positives
- Improve detection accuracy

## Configuration

Scoring thresholds can be adjusted in the configuration:
- Sensitivity levels
- Custom YARA rules
- Behavioral patterns
- Response actions 