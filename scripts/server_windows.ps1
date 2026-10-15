# XmasTunnel - Windows Server Setup & Launcher (PowerShell)
param (
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 0,
    [string]$Key = "",
    [switch]$Interactive = $false
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
& "$VenvPython" -m pip install -U pip setuptools --quiet
& "$VenvPython" -m pip install -r requirements.txt --quiet
& "$VenvPython" -m pip install -e . --quiet

# 3. Launch Server
if ($Interactive -or ($Port -eq 0 -and [string]::IsNullOrEmpty($Key))) {
    # Launch interactive wizard
    & "$VenvPython" -m xmastunnel server --interactive
} else {
    $EffectivePort = if ($Port -eq 0) { 8443 } else { $Port }
    Write-Host "[*] Starting XmasTunnel Server on ${HostAddress}:${EffectivePort}..." -ForegroundColor Green
    $ArgsList = @("-m", "xmastunnel", "server", "--host", $HostAddress, "-p", $EffectivePort)
    if ($Key) {
        $ArgsList += @("--key", $Key)
    }
    & "$VenvPython" @ArgsList
}
