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
# PDF engine (Typst): self-test nhanh, chỉ cảnh báo (không chặn khởi động).
if PDF_MSG="$("$VENV/bin/python" -m scanner.pdf.selftest --quiet 2>&1)"; then
  echo "$PDF_MSG" | tail -n 1
else
  echo "❌ $(echo "$PDF_MSG" | tail -n 1)" >&2
  echo "$PDF_MSG" | grep -E "FAIL" >&2 || true
  echo "   Xuất PDF sẽ không hoạt động tới khi sửa. Sửa: $VENV/bin/pip install --require-hashes -r api/requirements.txt" >&2
fi
# Mặc định CHỈ nghe localhost (an toàn). Mở LAN: VULNGUARD_BIND=0.0.0.0 (xem wiki "Truy cập từ máy khác trong LAN").
# VULNGUARD_HOST là alias deprecated của VULNGUARD_BIND.
if [ -z "${VULNGUARD_BIND:-}" ] && [ -n "${VULNGUARD_HOST:-}" ]; then
  echo "⚠️  VULNGUARD_HOST đã deprecated — dùng VULNGUARD_BIND." >&2
fi
HOST="${VULNGUARD_BIND:-${VULNGUARD_HOST:-127.0.0.1}}"
export VULNGUARD_BIND="$HOST"
# Chặn mở ra ngoài khi tắt xác thực (M-2): AUTH_ENABLED=false chỉ chạy được trên loopback.
case "$(printf '%s' "$AUTH_ENABLED" | tr '[:upper:]' '[:lower:]')" in
  false|0|no|off)
    case "$HOST" in
      127.0.0.1|localhost|::1) ;;
      *) echo "❌ AUTH_ENABLED=false không được phép khi VULNGUARD_BIND=$HOST (mở ra mạng không xác thực)."
         echo "   Bật AUTH_ENABLED=true hoặc dùng VULNGUARD_BIND=127.0.0.1."; exit 1 ;;
    esac ;;
esac
echo "─────────────────────────────────────────────"
echo "  VulnGuard PRODUCTION:  http://$HOST:$PORT"
case "$HOST" in
  127.0.0.1|localhost|::1)
    echo "  Chỉ truy cập được từ máy này. Mở cho máy khác trong LAN: VULNGUARD_BIND=0.0.0.0 (đọc wiki 'Truy cập từ máy khác trong LAN')." ;;
  *)
    echo "  ⚠️  Đang mở ra mạng ($HOST): đặt ALLOWED_HOSTS=<ip/hostname LAN>, tạo ADMIN/setup token trước, bật firewall;"
    echo "      khuyến nghị TLS (Caddy/nginx) + COOKIE_SECURE=true." ;;
esac
echo "  Lần đầu: tạo ADMIN trên trang đăng nhập — cần setup token (storage/setup_token hoặc VULNGUARD_SETUP_TOKEN)."
echo "  (Ctrl+C để dừng)"
echo "─────────────────────────────────────────────"
# D-14: trạng thái nằm trong bộ nhớ tiến trình (khoá scan, lockout, nonce, proxy, scheduler) → chỉ hỗ trợ 1 worker.
if [ "${VULNGUARD_WORKERS:-1}" != "1" ]; then
  echo "⚠️  VULNGUARD_WORKERS=${VULNGUARD_WORKERS} bị bỏ qua: VulnGuard chỉ hỗ trợ 1 worker/1 instance (trạng thái trong bộ nhớ)." >&2
fi
exec "$VENV/bin/uvicorn" api.main:app --host "$HOST" --port "$PORT" --workers 1
