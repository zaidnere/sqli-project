@echo off
REM Start the SQLi Scanner backend server (Windows)
REM Run from the backend\ directory

echo SQLi Scanner -- Backend
echo =======================

REM Check for virtual environment
if exist venv\Scripts\python.exe (
    set PYTHON=venv\Scripts\python.exe
) else (
    set PYTHON=python
)

REM Validate model weights (informational)
echo Checking model weights...
%PYTHON% scripts\validate_weights.py
echo.

echo Starting FastAPI server on http://127.0.0.1:8000
echo Press Ctrl+C to stop.
echo.

%PYTHON% -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
