# XmasTunnel - Windows Server Setup & Launcher (PowerShell)
param (
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 8443,
    [string]$Key = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location -LiteralPath $ProjectRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         XmasTunnel Server Setup & Launcher (Windows)     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python
$PythonExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonExe) {
    Write-Error "Python 3 is not installed or not in PATH. Please install Python from python.org"
}

# 2. Virtual Environment
$VenvPython = "$ProjectRoot\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Host "[*] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
}

Write-Host "[*] Updating dependencies..." -ForegroundColor Yellow
& "$VenvPython" -m pip install -U pip --quiet
& "$VenvPython" -m pip install -r requirements.txt --quiet

# 3. Launch Server
Write-Host "[*] Starting XmasTunnel Server on ${HostAddress}:${Port}..." -ForegroundColor Green
$ArgsList = @("-m", "xmastunnel", "server", "--host", $HostAddress, "-p", $Port)
if ($Key) {
    $ArgsList += @("--key", $Key)
}

& "$VenvPython" @ArgsList
