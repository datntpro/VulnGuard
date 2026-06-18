#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# VulnGuard — chạy thủ công (không qua systemd)
# Dùng khi debug, hoặc máy không có systemd.
# Usage: bash install/run.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

if [ ! -d "venv" ]; then
    echo "✗ Chưa thấy venv/ — hãy chạy install/install.sh trước (hoặc sudo nếu cần cài system deps)."
    exit 1
fi

if [ ! -f ".env" ]; then
    echo "✗ Chưa có .env — copy từ .env.native.example rồi sửa lại."
    exit 1
fi

set -a
source .env
set +a

export SEMGREP_HOME="${SEMGREP_HOME:-$PROJECT_DIR/.semgrep}"
mkdir -p storage/db storage/reports

echo "▶ VulnGuard chạy tại http://0.0.0.0:${VULNGUARD_PORT:-8080}  (Ctrl+C để dừng)"
exec "$PROJECT_DIR/venv/bin/uvicorn" api.main:app --host 0.0.0.0 --port "${VULNGUARD_PORT:-8080}"
