# VulnGuard — chay PRODUCTION (Windows). Lan dau tao ADMIN qua trang dang nhap (hoac dung setup.ps1).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv")) { Write-Host "Chua cai. Chay: .\setup.ps1"; exit 1 }
if (Test-Path ".env") { Get-Content .env | ForEach-Object { if ($_ -match '^\s*([^#][^=]*)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim()) } } }
$port = if ($env:VULNGUARD_PORT) { $env:VULNGUARD_PORT } else { "8080" }
if (-not $env:DATABASE_URL)   { $env:DATABASE_URL   = "sqlite:///$($PWD.Path -replace '\\','/')/storage/db/vulnguard.db" }
if (-not $env:AI_CONFIG_FILE) { $env:AI_CONFIG_FILE = "$PWD\storage\ai_config.json" }
if (-not $env:AUTH_ENABLED)   { $env:AUTH_ENABLED   = "true" }
if (-not $env:DEPLOY_MODE)    { $env:DEPLOY_MODE    = "native" }
New-Item -ItemType Directory -Force -Path "storage\db" | Out-Null
# Dua .venv\Scripts len dau PATH de scanner trong venv luon duoc tim thay (P0.1)
$env:PATH = "$PWD\.venv\Scripts;$env:PATH"
# Mac dinh chi nghe localhost; mo ra ngoai bang VULNGUARD_HOST=0.0.0.0 (P0.2)
$vhost = if ($env:VULNGUARD_HOST) { $env:VULNGUARD_HOST } else { "127.0.0.1" }
Write-Host "VulnGuard PRODUCTION: http://${vhost}:$port  (Ctrl+C de dung)"
& ".venv\Scripts\python.exe" -m uvicorn api.main:app --host $vhost --port $port
