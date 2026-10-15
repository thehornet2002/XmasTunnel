@echo off
setlocal
cd /d "%~dp0\.."

if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

.venv\Scripts\python.exe -m pip install -r requirements.txt --quiet

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0client_windows.ps1" %*
