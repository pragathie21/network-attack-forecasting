@echo off
title AI Network Attack Forecasting - SOC Dashboard
echo ============================================================
echo Starting AI CyberWatch SOC Frontend Dashboard (React + Vite)
echo ============================================================

cd /d "%~dp0frontend"

:: Check if Node is available
node --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not in PATH!
    pause
    exit /b 1
)

:: Install dependencies if node_modules missing
if not exist "node_modules" (
    echo [INFO] Installing frontend npm packages...
    call npm install
)

:: Start Vite dev server
echo.
echo [INFO] Starting Vite dev server on http://localhost:5173 ...
echo.
call npm run dev -- --open

pause
