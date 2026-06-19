#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# VulnGuard — Native Install Script (KHÔNG cần Docker)
# Mục tiêu: chạy được trên Ubuntu/Debian không cài Docker được
# (máy nội bộ bị hạn chế quyền, policy công ty, v.v.)
#
# Cài: Python venv + FastAPI app + scanner tools (Semgrep, Bandit,
# Trivy, pip-audit, Checkov, Hadolint, Grype, Gitleaks, detect-secrets)
# trực tiếp trên host, đăng ký systemd service để tự chạy.
#
# Usage:
#   sudo bash install/install.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# ── Màu output ──────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}▶${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
err()  { echo -e "${RED}✗${NC} $1"; }

# ── Phải chạy bằng root (cần apt-get, systemd, /etc) ──────────
if [ "$(id -u)" -ne 0 ]; then
    err "Script này cần chạy với quyền root."
    echo "  → Chạy lại: sudo bash install/install.sh"
    exit 1
fi

# ── Xác định project dir (parent của install/) ────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
log "Project dir: $PROJECT_DIR"

# ── User thực sự sở hữu project (không chạy service bằng root) ─
SERVICE_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
SERVICE_GROUP="$(id -gn "$SERVICE_USER" 2>/dev/null || echo "$SERVICE_USER")"
log "Service sẽ chạy với user: $SERVICE_USER"

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64"; ARCH_X="x86_64" ;;
    aarch64|arm64) ARCH="arm64"; ARCH_X="arm64" ;;
    *) err "Kiến trúc không hỗ trợ: $ARCH_RAW"; exit 1 ;;
esac
log "Kiến trúc: $ARCH_RAW ($ARCH)"

# ─────────────────────────────────────────────────────────────
# 1. System dependencies
# ─────────────────────────────────────────────────────────────
log "Cài system dependencies (apt)..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    curl wget git unzip ca-certificates gnupg apt-transport-https >/dev/null

PY_VERSION="$(python3 --version 2>&1 | awk '{print $2}')"
log "Python: $PY_VERSION"

# ─────────────────────────────────────────────────────────────
# 2. Scanner tools — binaries (giống Dockerfile, nhưng cài trực tiếp host)
# ─────────────────────────────────────────────────────────────

# 2.1 Trivy — qua apt repo chính thức
if ! command -v trivy >/dev/null 2>&1; then
    log "Cài Trivy..."
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor > /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list
    apt-get update -qq
    apt-get install -y trivy >/dev/null
else
    log "Trivy đã có — bỏ qua ($(trivy --version | head -1))"
fi

# 2.2 Gitleaks — binary release
if ! command -v gitleaks >/dev/null 2>&1; then
    log "Cài Gitleaks..."
    GL_ARCH="x64"; [ "$ARCH" = "arm64" ] && GL_ARCH="arm64"
    curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks
    chmod +x /usr/local/bin/gitleaks
else
    log "Gitleaks đã có — bỏ qua"
fi

# 2.3 Hadolint — binary release
if ! command -v hadolint >/dev/null 2>&1; then
    log "Cài Hadolint..."
    HL_ARCH="x86_64"; [ "$ARCH" = "arm64" ] && HL_ARCH="arm64"
    curl -sL "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-${HL_ARCH}" \
        -o /usr/local/bin/hadolint
    chmod +x /usr/local/bin/hadolint
else
    log "Hadolint đã có — bỏ qua"
fi

# 2.4 Grype — install script tự detect arch
if ! command -v grype >/dev/null 2>&1; then
    log "Cài Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin \
        || warn "Grype install thất bại — bỏ qua (không bắt buộc, chỉ ảnh hưởng CONTAINER scan)"
else
    log "Grype đã có — bỏ qua"
fi

# 2.5 Katana — web crawler dùng để build sitemap/endpoint inventory cho domain
#     (feature "Domain Sitemap / WAF Baseline")
if ! command -v katana >/dev/null 2>&1; then
    log "Cài Katana..."
    KT_ARCH="amd64"; [ "$ARCH" = "arm64" ] && KT_ARCH="arm64"
    KT_VERSION="1.5.0"
    curl -sL \
        "https://github.com/projectdiscovery/katana/releases/download/v${KT_VERSION}/katana_${KT_VERSION}_linux_${KT_ARCH}.zip" \
        -o /tmp/katana.zip \
    && unzip -p /tmp/katana.zip katana > /usr/local/bin/katana \
    && rm -f /tmp/katana.zip \
    && chmod +x /usr/local/bin/katana \
    || warn "Katana install thất bại — bỏ qua (chỉ ảnh hưởng tính năng Domain Sitemap)"
else
    log "Katana đã có — bỏ qua"
fi

# ─────────────────────────────────────────────────────────────
# 3. Python virtualenv + dependencies
# ─────────────────────────────────────────────────────────────
log "Tạo Python virtualenv tại $PROJECT_DIR/venv..."
python3 -m venv "$PROJECT_DIR/venv"
VENV_PIP="$PROJECT_DIR/venv/bin/pip"

"$VENV_PIP" install --no-cache-dir --upgrade pip -q

log "Cài API dependencies..."
"$VENV_PIP" install --no-cache-dir -r "$PROJECT_DIR/api/requirements.txt" -q

log "Cài scanner Python packages (Semgrep, Bandit, Checkov, detect-secrets, pip-audit)..."
"$VENV_PIP" install --no-cache-dir -q \
    semgrep \
    "bandit[toml]" \
    checkov \
    detect-secrets \
    pip-audit

# Re-install API packages để tránh version bị scanner tools override
"$VENV_PIP" install --no-cache-dir -r "$PROJECT_DIR/api/requirements.txt" -q

# Pre-cache Semgrep rules (tránh tải lại mỗi lần scan)
log "Pre-cache Semgrep rules..."
export SEMGREP_HOME="$PROJECT_DIR/.semgrep"
"$PROJECT_DIR/venv/bin/semgrep" \
    --config p/python --config p/security-audit --config p/owasp-top-ten \
    --metrics=off --dry-run /dev/null >/dev/null 2>&1 || true

# ─────────────────────────────────────────────────────────────
# 4. Storage + .env
# ─────────────────────────────────────────────────────────────
log "Tạo thư mục storage..."
mkdir -p "$PROJECT_DIR/storage/db" "$PROJECT_DIR/storage/reports"

if [ ! -f "$PROJECT_DIR/.env" ]; then
    log "Tạo .env từ .env.native.example..."
    cp "$PROJECT_DIR/.env.native.example" "$PROJECT_DIR/.env"
    # Set absolute path đúng theo project dir thật
    sed -i "s#sqlite:////opt/vulnguard/storage/db/vulnguard.db#sqlite:///${PROJECT_DIR}/storage/db/vulnguard.db#" "$PROJECT_DIR/.env"
    sed -i "s#/opt/vulnguard/storage/scanner_config.json#${PROJECT_DIR}/storage/scanner_config.json#" "$PROJECT_DIR/.env"
    warn "Nhớ mở .env và sửa SCAN_WORKSPACE trỏ đúng thư mục chứa source code cần scan."
else
    log ".env đã tồn tại — không ghi đè."
fi

chown -R "$SERVICE_USER:$SERVICE_GROUP" "$PROJECT_DIR/storage" "$PROJECT_DIR/venv" "$PROJECT_DIR/.env" 2>/dev/null || true

# ─────────────────────────────────────────────────────────────
# 5. systemd service
# ─────────────────────────────────────────────────────────────
VULNGUARD_PORT="$(grep -m1 '^VULNGUARD_PORT=' "$PROJECT_DIR/.env" 2>/dev/null | cut -d= -f2 || echo 8080)"
VULNGUARD_PORT="${VULNGUARD_PORT:-8080}"

log "Tạo systemd service (port $VULNGUARD_PORT)..."
sed \
    -e "s#__PROJECT_DIR__#${PROJECT_DIR}#g" \
    -e "s#__SERVICE_USER__#${SERVICE_USER}#g" \
    -e "s#__SERVICE_GROUP__#${SERVICE_GROUP}#g" \
    -e "s#__VULNGUARD_PORT__#${VULNGUARD_PORT}#g" \
    "$SCRIPT_DIR/vulnguard.service.template" > /etc/systemd/system/vulnguard.service

systemctl daemon-reload
systemctl enable vulnguard.service >/dev/null
systemctl restart vulnguard.service

sleep 2
if systemctl is-active --quiet vulnguard.service; then
    log "VulnGuard đang chạy! ✅"
else
    err "Service không start được — xem log: journalctl -u vulnguard -n 50"
    exit 1
fi

# ─────────────────────────────────────────────────────────────
# 6. Tóm tắt
# ─────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
echo " ✅ VulnGuard đã cài xong (native, không Docker)"
echo "─────────────────────────────────────────────"
echo "  Web UI    : http://localhost:${VULNGUARD_PORT}"
echo "  API docs  : http://localhost:${VULNGUARD_PORT}/docs"
echo "  .env      : $PROJECT_DIR/.env"
echo "  Logs      : journalctl -u vulnguard -f"
echo "  Service   : systemctl {status|restart|stop} vulnguard"
echo ""
echo "  ⚠ Nhớ sửa SCAN_WORKSPACE trong .env, rồi:"
echo "    systemctl restart vulnguard"
echo ""
echo "  AI Analysis cần Ollama chạy trên host:"
echo "    curl -fsSL https://ollama.com/install.sh | sh"
echo "    ollama pull llama3.2"
echo "─────────────────────────────────────────────"
