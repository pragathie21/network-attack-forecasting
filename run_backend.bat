@echo off
title AI Network Attack Forecasting - Backend Server
echo ============================================================
echo Starting AI Network Attack Forecasting FastAPI Backend
echo ============================================================

cd /d "%~dp0backend"

:: Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b 1
)

:: Install dependencies if needed
echo Checking Python dependencies...
python -m pip install -r requirements.txt

:: Train model if artifacts are missing
if not exist "models\model.joblib" (
    echo [INFO] Trained ML model not found. Training model now...
    python ml_pipeline\train_model.py
)

:: Start Uvicorn Server
echo.
echo [INFO] Starting FastAPI on http://127.0.0.1:8000 ...
echo [INFO] Interactive Swagger Documentation: http://127.0.0.1:8000/docs
echo.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

pause
