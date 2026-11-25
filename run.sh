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
# Đưa .venv/bin LÊN ĐẦU PATH để các scanner (semgrep, bandit, pip-audit,
# detect-secrets…) cài trong venv luôn tìm thấy — nếu không, scan sẽ âm thầm
# bỏ qua tool mà vẫn báo "0 lỗi" (P0.1).
export PATH="$PWD/$VENV/bin:$HOME/.local/bin:$PATH"
# Mặc định CHỈ nghe localhost (an toàn). Mở ra ngoài bằng VULNGUARD_HOST=0.0.0.0 (P0.2).
HOST="${VULNGUARD_HOST:-127.0.0.1}"
# Chặn mở ra ngoài khi tắt xác thực (M-2): AUTH_ENABLED=false chỉ chạy được trên loopback.
case "$(printf '%s' "$AUTH_ENABLED" | tr '[:upper:]' '[:lower:]')" in
  false|0|no|off)
    case "$HOST" in
      127.0.0.1|localhost|::1) ;;
      *) echo "❌ AUTH_ENABLED=false không được phép khi VULNGUARD_HOST=$HOST (mở ra mạng không xác thực)."
         echo "   Bật AUTH_ENABLED=true hoặc dùng VULNGUARD_HOST=127.0.0.1."; exit 1 ;;
    esac ;;
esac
echo "─────────────────────────────────────────────"
echo "  VulnGuard PRODUCTION:  http://$HOST:$PORT"
[ "$HOST" = "0.0.0.0" ] && echo "  ⚠️  Đang mở ra TẤT CẢ network interface (VULNGUARD_HOST=0.0.0.0). Hãy đảm bảo có auth + firewall."
echo "  Lần đầu: tạo tài khoản ADMIN ngay trên trang đăng nhập."
echo "  (Ctrl+C để dừng)"
echo "─────────────────────────────────────────────"
# D-14: trạng thái nằm trong bộ nhớ tiến trình (khoá scan, lockout, nonce, proxy, scheduler) → chỉ hỗ trợ 1 worker.
if [ "${VULNGUARD_WORKERS:-1}" != "1" ]; then
  echo "⚠️  VULNGUARD_WORKERS=${VULNGUARD_WORKERS} bị bỏ qua: VulnGuard chỉ hỗ trợ 1 worker/1 instance (trạng thái trong bộ nhớ)." >&2
fi
exec "$VENV/bin/uvicorn" api.main:app --host "$HOST" --port "$PORT" --workers 1
