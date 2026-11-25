#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# VulnGuard — chạy DEMO local (native, KHÔNG cần Docker)
# Yêu cầu: Python 3.11+ . Không cần nmap/nuclei/Ollama cho bản demo
# (dữ liệu demo đã được seed sẵn, không chạy scan thật).
#   bash run_demo.sh          # cài deps, seed dữ liệu demo, chạy server
#   bash run_demo.sh --no-seed # chạy lại không seed lại (giữ dữ liệu)
# ──────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

PORT="${VULNGUARD_PORT:-8080}"
VENV=".venv-demo"
export DEMO_DIR="${DEMO_DIR:-$PWD/storage/demo}"
export DATABASE_URL="sqlite:///$DEMO_DIR/db/vulnguard.db"
export AI_CONFIG_FILE="$DEMO_DIR/ai_config.json"
export AUTH_ENABLED="true"
export APP_ENV="production"
export DEPLOY_MODE="native"
export VULNGUARD_DEMO="1"   # giữ dữ liệu demo đang-chờ-duyệt (bỏ qua cleanup khởi động)
mkdir -p "$DEMO_DIR/db"

PY="python3"
command -v "$PY" >/dev/null || { echo "❌ Cần Python 3.11+"; exit 1; }

if [ ! -d "$VENV" ]; then
  echo "📦 Tạo virtualenv + cài dependencies (lần đầu ~1-2 phút)…"
  "$PY" -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q -r api/requirements.txt
fi
PYBIN="$VENV/bin/python"

if [ "${1:-}" != "--no-seed" ]; then
  echo "🌱 Seed dữ liệu demo…"
  "$PYBIN" -m scripts.seed_demo
fi

echo ""
echo "─────────────────────────────────────────────"
echo "  VulnGuard DEMO đang chạy:  http://localhost:$PORT"
echo "  Đăng nhập:  demo@vulnguard.local  /  VulnGuardDemo!"
echo "  (Ctrl+C để dừng)"
echo "─────────────────────────────────────────────"
# Demo: mặc định loopback như phần còn lại; mở LAN bằng VULNGUARD_BIND=0.0.0.0 (demo có tài khoản demo công khai!).
exec "$VENV/bin/uvicorn" api.main:app --host "${VULNGUARD_BIND:-127.0.0.1}" --port "$PORT"
