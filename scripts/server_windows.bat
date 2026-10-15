@echo off
setlocal
cd /d "%~dp0\.."

if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

.venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
.venv\Scripts\python.exe -m xmastunnel server --host 0.0.0.0 -p 8443 %*
pause
