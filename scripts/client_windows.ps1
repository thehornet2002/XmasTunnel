# XmasTunnel - Windows Client Setup & Launcher (PowerShell)
param (
    [string]$Server = "",
    [int]$Port = 8443,
    [string]$Key = "",
    [switch]$XmasProbe = $false
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location -LiteralPath $ProjectRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         XmasTunnel Client Setup & Launcher (Windows)     " -ForegroundColor Cyan
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

# 3. Interactive inputs if omitted
if (-not $Server) {
    $Server = Read-Host "Enter Server IP Address [default: 127.0.0.1]"
    if (-not $Server) { $Server = "127.0.0.1" }
}

if (-not $Key) {
    $Key = Read-Host "Enter Pre-Shared Key (PSK)"
}

if (-not $XmasProbe) {
    $ProbeChoice = Read-Host "Enable Xmas Tree probe before connection? (y/N)"
    if ($ProbeChoice -match "^[Yy]") {
        $XmasProbe = $true
    }
}

Write-Host "[*] Connecting to ${Server}:${Port}..." -ForegroundColor Green
$ArgsList = @("-m", "xmastunnel", "client", "-s", $Server, "-p", $Port, "--key", $Key)
if ($XmasProbe) {
    $ArgsList += "--xmas-probe"
}

& "$VenvPython" @ArgsList
