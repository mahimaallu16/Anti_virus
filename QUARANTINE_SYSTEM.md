# Quarantine System Documentation

## Overview
The quarantine system isolates suspicious files to prevent them from causing harm while preserving them for analysis and potential restoration.

## File Types That Get Quarantined

### 🚨 High-Risk File Types (Score: 81-100)
**Immediate quarantine recommended**

| File Type | Extensions | Risk Level | Examples |
|-----------|------------|------------|----------|
| **Executables** | `.exe`, `.dll`, `.sys`, `.drv` | Critical | Malware, suspicious programs |
| **Scripts** | `.js`, `.vbs`, `.ps1`, `.bat`, `.cmd` | High | Malicious scripts, automation tools |
| **Archives** | `.zip`, `.rar`, `.7z`, `.tar`, `.gz` | High | Compressed malware, suspicious packages |

### ⚠️ Medium-Risk File Types (Score: 61-80)
**Quarantine based on behavior and location**

| File Type | Extensions | Risk Level | Examples |
|-----------|------------|------------|----------|
| **Office Documents** | `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx` | Medium | Macro-enabled documents |
| **PDFs** | `.pdf` | Medium | PDFs with embedded scripts |
| **System Files** | Various | Medium | Files in system directories |

### 🔍 Low-Risk File Types (Score: 31-60)
**Quarantine only with specific indicators**

| File Type | Extensions | Risk Level | Examples |
|-----------|------------|------------|----------|
| **Images** | `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp` | Low | Steganography, image-based attacks |
| **Media** | `.mp3`, `.mp4`, `.avi`, `.mov`, `.wav` | Low | Media files with embedded code |
| **Text** | `.txt`, `.log`, `.ini`, `.cfg` | Low | Configuration files with suspicious content |

## Quarantine Criteria

### 1. Threat Score Based
- **Score 81-100**: Automatic quarantine
- **Score 61-80**: Quarantine with user confirmation
- **Score 31-60**: Alert and recommend quarantine
- **Score 0-30**: Monitor only

### 2. Location Based
- **System directories**: `system32`, `syswow64`
- **Temporary folders**: `temp`, `tmp`
- **Download directories**: Recent downloads
- **Suspicious paths**: Unusual locations

### 3. Behavior Based
- **YARA rule matches**: Known malware patterns
- **Suspicious activities**: Network communication, registry changes
- **File modifications**: Unusual file operations

## Quarantine Process

### 1. File Analysis
```python
# Get file information
file_name = os.path.basename(file_path)
file_extension = os.path.splitext(file_name)[1].lower()
file_size = os.path.getsize(file_path)
file_type = determine_file_type(file_extension)
```

### 2. Threat Assessment
```python
# Calculate threat score
threat_score = calculate_threat_score(file_path, file_content, file_metadata)
threat_type = identify_threat_type(file_path, file_content)
```

### 3. Quarantine Action
```python
# Move file to quarantine
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
quarantine_filename = f"{timestamp}_{file_name}"
quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)
shutil.move(file_path, quarantine_path)
```

### 4. Record Creation
```python
# From the quarantine endpoint
quarantine_record = {
    "threat_score": data.get("threat_score", 0),  # Score from scan
    "threat_type": data.get("threat_type", "Unknown"),
    "quarantine_reason": data.get("quarantine_reason", "Suspicious file"),
    "original_path": file_path,
    "quarantine_path": quarantine_path,
    "filename": file_name,
    "file_type": file_type,
    "file_extension": file_extension,
    "file_size": file_size,
    "quarantine_date": datetime.now().isoformat(),
    "status": "quarantined"
}
```

## Quarantine Database Structure

### File Record Fields
| Field | Type | Description |
|-------|------|-------------|
| `original_path` | String | Original file location |
| `quarantine_path` | String | Quarantine location |
| `filename` | String | File name |
| `file_type` | String | Categorized file type |
| `file_extension` | String | File extension |
| `file_size` | Integer | File size in bytes |
| `threat_score` | Integer | Threat score (0-100) |
| `threat_type` | String | Type of threat detected |
| `quarantine_reason` | String | Reason for quarantine |
| `quarantine_date` | String | ISO timestamp |
| `status` | String | Current status |

## File Type Detection

### Executable Files
- **Extensions**: `.exe`, `.dll`, `.sys`, `.drv`
- **Risk**: High - Can execute code
- **Detection**: YARA rules, behavior analysis
- **Quarantine**: Automatic for suspicious ones

### Script Files
- **Extensions**: `.js`, `.vbs`, `.ps1`, `.bat`, `.cmd`
- **Risk**: High - Can automate malicious actions
- **Detection**: Content analysis, execution patterns
- **Quarantine**: Based on content and behavior

### Archive Files
- **Extensions**: `.zip`, `.rar`, `.7z`, `.tar`, `.gz`
- **Risk**: Medium-High - Can contain malware
- **Detection**: Content scanning, nested file analysis
- **Quarantine**: If suspicious content detected

### Office Documents
- **Extensions**: `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`
- **Risk**: Medium - Macro viruses
- **Detection**: Macro analysis, embedded content
- **Quarantine**: If macros or suspicious content found

### Media Files
- **Extensions**: `.mp3`, `.mp4`, `.avi`, `.mov`, `.wav`
- **Risk**: Low - Steganography, embedded code
- **Detection**: Metadata analysis, content scanning
- **Quarantine**: Rare, only with specific indicators

## Quarantine Statistics

### File Type Distribution
The system tracks:
- Total quarantined files
- File type breakdown
- Threat type distribution
- Average threat scores
- Score ranges (min/max)

### Example Statistics
```json
{
  "total_quarantined": 15,
  "file_types": {
    "Executable": 8,
    "Script": 4,
    "Archive": 2,
    "Office Document": 1
  },
  "threat_types": {
    "Signature: Suspicious_Executable": 6,
    "Behavior: Suspicious file location": 5,
    "Suspicious JavaScript file": 4
  },
  "average_threat_score": 78.5,
  "max_threat_score": 95,
  "min_threat_score": 60
}
```

## Quarantine Management

### Restore Files
- Files can be restored to original location
- Original directory structure preserved
- Threat assessment re-evaluated

### Delete Files
- Permanent removal from quarantine
- Cannot be recovered
- Use with caution

### File Analysis
- Detailed threat information
- File metadata preservation
- Quarantine history tracking

## Security Considerations

### Isolation
- Quarantined files are isolated from system
- No execution possible from quarantine
- Secure storage with access controls

### Analysis
- Files preserved for forensic analysis
- Metadata maintained for investigation
- Threat intelligence gathering

### Recovery
- Safe restoration process
- Verification before restoration
- Backup of quarantine records

## Best Practices

### Regular Review
- Review quarantined files regularly
- Analyze false positives
- Update detection rules

### Threat Intelligence
- Share threat data
- Update YARA rules
- Improve detection accuracy

### Documentation
- Maintain quarantine logs
- Document threat patterns
- Track system improvements 