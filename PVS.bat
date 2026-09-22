@echo off
title PVS - Personal Vulnerability Scanner Assistant
cd /d "%~dp0"
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe -m pvs wizard
) else (
    python -m pvs wizard
)
pause
