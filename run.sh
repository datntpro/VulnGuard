#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# VulnGuard — chạy PRODUCTION (native, không seed dữ liệu demo).
# Lần đầu mở app sẽ yêu cầu tạo tài khoản ADMIN.
#   bash run.sh                 # chạy tại http://localhost:${VULNGUARD_PORT:-8080}
# Biến môi trường đọc từ .env nếu có (xem .env.native.example).
# ──────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] && set -a && . ./.env && set +a
PORT="${VULNGUARD_PORT:-8080}"
VENV="${VULNGUARD_VENV:-.venv}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///$PWD/storage/db/vulnguard.db}"
export AI_CONFIG_FILE="${AI_CONFIG_FILE:-$PWD/storage/ai_config.json}"
export SCANNER_CONFIG_FILE="${SCANNER_CONFIG_FILE:-$PWD/storage/scanner_config.json}"
export AUTH_ENABLED="${AUTH_ENABLED:-true}"
export APP_ENV="${APP_ENV:-production}"
export DEPLOY_MODE="${DEPLOY_MODE:-native}"
mkdir -p "$PWD/storage/db" "$PWD/storage/documents"

[ -d "$VENV" ] || { echo "❌ Chưa cài. Chạy: bash setup.sh"; exit 1; }
echo "─────────────────────────────────────────────"
echo "  VulnGuard PRODUCTION:  http://localhost:$PORT"
echo "  Lần đầu: tạo tài khoản ADMIN ngay trên trang đăng nhập."
echo "  (Ctrl+C để dừng)"
echo "─────────────────────────────────────────────"
WORKERS="${VULNGUARD_WORKERS:-1}"
exec "$VENV/bin/uvicorn" api.main:app --host 0.0.0.0 --port "$PORT" --workers "$WORKERS"
