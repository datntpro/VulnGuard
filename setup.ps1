# VulnGuard — cài đặt (Windows). Logic chung ở scripts/setup.py (đa nền tảng).
# Chạy:  powershell -ExecutionPolicy Bypass -File setup.ps1
#        (hoặc)  .\setup.ps1 --check   /   .\setup.ps1 --docker
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Write-Host "Can Python 3.11+ (python.org)"; exit 1 }
& $py.Source "scripts/setup.py" @args
