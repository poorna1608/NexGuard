@echo off
title NexGuard - Intelligent Phishing & Malicious URL Detection Platform
color 0B
cls
echo =====================================================================
echo           NEXGUARD CYBERSECURITY SOC PLATFORM
echo              Detect. Analyze. Protect.
echo =====================================================================
echo.
cd /d "%~dp0"

echo [*] Opening NexGuard website in your default browser...
start http://localhost:3000

echo [*] Starting NexGuard Local Development Server on port 3000...
echo [*] Press Ctrl+C at any time to stop the server.
echo.

npm run dev
pause
