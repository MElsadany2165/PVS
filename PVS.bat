@echo off
setlocal
title PVS - Personal Vulnerability Scanner & Remediation Engine
cd /d "%~dp0"

if exist "venv\Scripts\python.exe" (
    set "PYTHON_EXE=venv\Scripts\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

if "%~1"=="" (
    "%PYTHON_EXE%" -m pvs wizard
    echo.
    echo Press any key to exit...
    pause >nul
) else (
    "%PYTHON_EXE%" -m pvs %*
)
