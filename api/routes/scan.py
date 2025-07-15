"""
Scan API routes for antivirus system.

This file contains FastAPI endpoints for scan operations.
"""

from fastapi import APIRouter, UploadFile, File
from services.scan_service import ScanService

router = APIRouter()
scan_service = ScanService()

@router.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    # Save uploaded file to disk (stub)
    file_path = f"uploads/{file.filename}"
    with open(file_path, "wb") as f:
        f.write(await file.read())
    result = await scan_service.scan_file(file_path)
    return result 