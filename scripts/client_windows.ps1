# XmasTunnel - Windows Client Setup & Launcher (PowerShell)
param (
    [string]$Token = "",
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
& "$VenvPython" -m pip install -U pip setuptools --quiet
& "$VenvPython" -m pip install -r requirements.txt --quiet
& "$VenvPython" -m pip install -e . --quiet

# 3. Handle Token or Interactive Inputs
if ($Token -or ($Server -match "^xmas://")) {
    $EffectiveToken = if ($Token) { $Token } else { $Server }
    Write-Host "[*] Connecting using Client Configuration Token..." -ForegroundColor Green
    & "$VenvPython" -m xmastunnel client --token "$EffectiveToken"
    exit 0
}

if (-not $Server -and -not $Key) {
    $InputVal = Read-Host "Enter Client Config Token (xmas://...) or Server IP"
    if ($InputVal -match "^xmas://") {
        Write-Host "[*] Connecting using Client Configuration Token..." -ForegroundColor Green
        & "$VenvPython" -m xmastunnel client --token "$InputVal"
        exit 0
    }
    $Server = if ($InputVal) { $InputVal } else { "127.0.0.1" }
    $PortStr = Read-Host "Enter Server Port [default: 8443]"
    if ($PortStr) { $Port = [int]$PortStr }
    $Key = Read-Host "Enter Pre-Shared Key (PSK)"
    $ProbeChoice = Read-Host "Enable Xmas Tree probe before connection? (Y/n)"
    if ($ProbeChoice -notmatch "^[Nn]") {
        $XmasProbe = $true
    }
}

Write-Host "[*] Connecting to ${Server}:${Port}..." -ForegroundColor Green
$ArgsList = @("-m", "xmastunnel", "client", "-s", $Server, "-p", $Port, "--key", $Key)
if ($XmasProbe) {
    $ArgsList += "--xmas-probe"
}

& "$VenvPython" @ArgsList
