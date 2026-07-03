#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# VulnGuard Coworker Host Service — chạy trực tiếp trên máy host
# (KHÔNG chạy trong Docker — giống Ollama, để có thể đọc/sửa
# bất kỳ folder nào người dùng cấp quyền trên máy thật).
#
# Usage: bash coworker_host/run.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/.coworker_venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "▶ Tạo venv riêng cho coworker_host tại $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
fi

export COWORKER_DATA_DIR="${COWORKER_DATA_DIR:-$HOME/.vulnguard_coworker}"
PORT="${COWORKER_HOST_PORT:-8765}"

echo "▶ VulnGuard Coworker Host chạy tại http://127.0.0.1:${PORT}  (Ctrl+C để dừng)"
echo "  Data dir (granted folders, whitelist): ${COWORKER_DATA_DIR}"
exec "$VENV_DIR/bin/uvicorn" coworker_host.app:app --app-dir "$PROJECT_DIR" --host 127.0.0.1 --port "$PORT"
