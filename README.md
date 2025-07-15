# Antivirus Project

A comprehensive antivirus solution with React frontend and FastAPI backend.

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm

### Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Node.js dependencies:**
   ```bash
   npm run install:all
   ```

### Starting the Application

You have several options to start both frontend and backend simultaneously:

#### Option 1: Using npm scripts (Recommended)
```bash
npm start
```

#### Option 2: Using the dev script
```bash
npm run dev
```

#### Option 3: Windows Batch Script
```bash
start-dev.bat
```

#### Option 4: Unix/Linux Shell Script
```bash
chmod +x start-dev.sh
./start-dev.sh
```

#### Option 5: Manual Start
1. Start the backend:
   ```bash
   python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```

2. In a new terminal, start the frontend:
   ```bash
   cd frontend
   npm start
   ```

### Access URLs
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### Project Structure
```
antivirus_project/
├── app.py                 # FastAPI backend
├── frontend/              # React frontend
├── antivirus.py/          # Core antivirus modules
├── signatures/            # YARA signature files
├── uploads/               # File upload directory
└── quarantine/            # Quarantined files
```

### Features
- Real-time file scanning
- YARA signature-based detection
- File quarantine management
- System monitoring
- Web-based dashboard 