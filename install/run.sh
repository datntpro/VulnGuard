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
export PATH="$PROJECT_DIR/venv/bin:$PATH"   # scanner trong venv luôn tìm thấy (P0.1)
mkdir -p storage/db storage/reports

if [ -z "${VULNGUARD_BIND:-}" ] && [ -n "${VULNGUARD_HOST:-}" ]; then
    echo "⚠️  VULNGUARD_HOST đã deprecated — dùng VULNGUARD_BIND." >&2
fi
HOST="${VULNGUARD_BIND:-${VULNGUARD_HOST:-127.0.0.1}}"   # mặc định localhost (P0.2)
export VULNGUARD_BIND="$HOST"
case "$(printf '%s' "${AUTH_ENABLED:-true}" | tr '[:upper:]' '[:lower:]')" in
  false|0|no|off)
    case "$HOST" in
      127.0.0.1|localhost|::1) ;;
      *) echo "❌ AUTH_ENABLED=false không được phép khi VULNGUARD_BIND=$HOST"; exit 1 ;;
    esac ;;
esac
echo "▶ VulnGuard chạy tại http://$HOST:${VULNGUARD_PORT:-8080}  (Ctrl+C để dừng)"
exec "$PROJECT_DIR/venv/bin/uvicorn" api.main:app --host "$HOST" --port "${VULNGUARD_PORT:-8080}" --workers 1
