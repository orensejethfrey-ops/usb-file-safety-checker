@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
  echo Python 3 is required. Install it from python.org, then run this file again.
  pause
  exit /b 1
)

py -3 defender_server.py
if errorlevel 1 pause
