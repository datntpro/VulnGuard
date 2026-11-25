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

# Đọc CHỌN LỌC vài khóa từ .env (KHÔNG source/execute file — N-8) để DÙNG CHUNG
# VULNGUARD_COWORKER_TOKEN với app trong Docker. Biến đã có trong môi trường được ưu tiên.
_envval() {
    grep -E "^$1=" "$PROJECT_DIR/.env" 2>/dev/null | tail -n1 | cut -d= -f2- \
        | sed -e 's/^["'\'']//' -e 's/["'\'']$//' || true
}
if [ -f "$PROJECT_DIR/.env" ]; then
    for _k in VULNGUARD_COWORKER_TOKEN COWORKER_EXEC_MODE COWORKER_ALLOWED_ROOTS COWORKER_HOST_PORT COWORKER_ALLOWED_HOSTS; do
        if [ -z "${!_k:-}" ]; then
            _v="$(_envval "$_k")"
            if [ -n "$_v" ]; then export "$_k=$_v"; fi
        fi
    done
fi
if [ -z "${VULNGUARD_COWORKER_TOKEN:-}" ]; then
    echo "⚠ VULNGUARD_COWORKER_TOKEN chưa đặt. Service sẽ tự sinh token, nhưng app"
    echo "  trong Docker sẽ KHÔNG khớp → Co-work bị 401. Hãy đặt cùng giá trị ở .env:"
    echo "    echo \"VULNGUARD_COWORKER_TOKEN=\$(openssl rand -hex 32)\" >> $PROJECT_DIR/.env"
fi

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
echo "  Exec mode: ${COWORKER_EXEC_MODE:-safe}  (safe = chỉ lệnh đọc; trusted = lệnh khác cần xác nhận)"
exec "$VENV_DIR/bin/uvicorn" coworker_host.app:app --app-dir "$PROJECT_DIR" --host 127.0.0.1 --port "$PORT"
