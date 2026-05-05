@echo off
REM Start the SQLi Scanner backend server (Windows)
REM Run from the backend\ directory

echo SQLi Scanner -- Backend
echo =======================

REM Check for virtual environment and activate it
if exist venv\Scripts\activate.bat (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
    set PYTHON=python
) else (
    echo Virtual environment not found. Using system Python...
    set PYTHON=python
)

echo.

REM Validate model weights (informational)
echo Checking model weights...
%PYTHON% scripts\validate_weights.py
echo.

echo Starting FastAPI server on http://127.0.0.1:8000
echo Press Ctrl+C to stop.
echo.

%PYTHON% -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000


@REM test