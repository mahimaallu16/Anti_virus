@echo off
echo Starting Antivirus Project - Frontend and Backend
echo.

echo Starting Backend (FastAPI) on port 8000...
start "Backend" cmd /k "python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000"

echo Waiting 3 seconds for backend to initialize...
timeout /t 3 /nobreak > nul

echo Starting Frontend (React) on port 3000...
start "Frontend" cmd /k "cd frontend && npm start"

echo.
echo Both services are starting...
echo Backend: http://localhost:8000
echo Frontend: http://localhost:3000
echo.
echo Press any key to close this window...
pause > nul 