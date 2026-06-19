#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# VulnGuard — Gỡ bản native install
# Xóa systemd service. Giữ lại storage/ (database, reports) và .env
# trừ khi truyền --purge.
#
# Usage:
#   sudo bash install/uninstall.sh           # gỡ service, giữ data
#   sudo bash install/uninstall.sh --purge   # gỡ service + venv + storage (XÓA DATA)
# ─────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}▶${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Cần chạy với quyền root: sudo bash install/uninstall.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true

log "Dừng và gỡ systemd service..."
systemctl stop vulnguard.service 2>/dev/null || true
systemctl disable vulnguard.service 2>/dev/null || true
rm -f /etc/systemd/system/vulnguard.service
systemctl daemon-reload

log "Đã gỡ service. Scanner tools (trivy, gitleaks, hadolint, grype, katana) được giữ lại"
echo "  (chúng cài ở /usr/local/bin, không liên quan riêng VulnGuard — gỡ tay nếu cần)."

if [ "$PURGE" = true ]; then
    warn "PURGE: xóa venv/ và storage/ (DATABASE + REPORTS sẽ MẤT)..."
    read -p "Xác nhận xóa toàn bộ data tại $PROJECT_DIR/storage? (y/N) " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        rm -rf "$PROJECT_DIR/venv" "$PROJECT_DIR/storage" "$PROJECT_DIR/.semgrep" "$PROJECT_DIR/.env"
        log "Đã xóa venv, storage, .env."
    else
        log "Bỏ qua xóa data — chỉ gỡ service."
    fi
else
    log "Giữ nguyên venv/, storage/, .env. Dùng --purge nếu muốn xóa sạch."
fi

echo ""
log "Gỡ xong."
