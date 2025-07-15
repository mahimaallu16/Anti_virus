# Antivirus Project Architecture

This document describes the modular structure and responsibilities of each major file and directory in the antivirus project.

## Directory Structure & Responsibilities

### core/
- **Purpose:** Core antivirus logic (scanning, detection, quarantine, monitoring).
- **scanner/**: File and process scanning logic.
- **detection/**: Detection engines (signature, heuristic, behavioral).
- **quarantine/**: Quarantine management logic.
- **monitoring/**: Real-time protection and monitoring logic.

### services/
- **Purpose:** Business logic that coordinates between the API and core modules.
- **scan_service.py**: Handles scan requests, coordinates with core scanners, manages scan history.
- **file_service.py**: Handles file operations (upload, download, delete, restore).
- **alert_service.py**: Manages alerts and notifications.
- **quarantine_service.py**: Manages quarantine actions (add, remove, restore).
- **auth_service.py**: Handles authentication and user management.

### api/
- **Purpose:** API layer (FastAPI endpoints, middleware, websockets).
- **routes/**: Each file contains related API endpoints (e.g., scan, quarantine, auth).
- **middleware/**: Custom FastAPI middleware.
- **websockets/**: WebSocket handlers for real-time features.

### config/
- **Purpose:** Centralized configuration and constants.
- **constants.py**: All project-wide constants (paths, thresholds, etc.).
- **settings.py**: Loads and validates settings (using Pydantic).

### utils/
- **Purpose:** Utility functions for file, security, and config operations.
- **file_utils.py**: File operations (hashing, archive extraction, safe filenames, etc.).
- **security_utils.py**: Security-related helpers (digital signature, whitelisting).
- **config_utils.py**: Helpers for loading/saving config files.

### database.py
- **Purpose:** Sets up the SQLAlchemy database engine and session.

### models.py
- **Purpose:** SQLAlchemy ORM models for users, scan history, settings, etc.

### auth.py
- **Purpose:** Authentication logic (JWT, password hashing, user validation).

### app.py
- **Purpose:** FastAPI app initialization and main entry point. Only app setup and route inclusion—no business logic.

### signatures/
- **Purpose:** YARA and other signature files for malware detection.

### quarantine/
- **Purpose:** Directory for storing quarantined files.

### uploads/
- **Purpose:** Directory for storing uploaded files.

### frontend/
- **Purpose:** React frontend for the antivirus dashboard.

---

## How to Use This Structure
- Add new features by creating new modules/services, not by expanding app.py.
- Keep business logic in services/ and core detection/scanning in core/.
- API endpoints should only call services, not core logic directly.
- Utilities should be stateless and reusable.

---

For more details, see the docstrings in each module. 