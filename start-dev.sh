#!/bin/bash

echo "Starting Antivirus Project - Frontend and Backend"
echo

echo "Starting Backend (FastAPI) on port 8000..."
python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "Waiting 3 seconds for backend to initialize..."
sleep 3

echo "Starting Frontend (React) on port 3000..."
cd frontend && npm start &
FRONTEND_PID=$!

echo
echo "Both services are starting..."
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:3000"
echo
echo "Press Ctrl+C to stop both services..."

# Wait for user to interrupt
wait

# Cleanup on exit
echo "Stopping services..."
kill $BACKEND_PID 2>/dev/null
kill $FRONTEND_PID 2>/dev/null
echo "Services stopped." 