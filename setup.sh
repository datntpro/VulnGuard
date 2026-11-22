#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  VulnGuard — Trình cài đặt tương tác (chọn công cụ cần dùng)
#  Hỗ trợ: Docker  HOẶC  Native (Python venv + công cụ hệ thống)
#  Dùng:   bash setup.sh
#          bash setup.sh --tools "sast sca web pentest" --no-run   (không tương tác)
#          bash setup.sh --check                                    (chỉ kiểm tra tool)
# ══════════════════════════════════════════════════════════════
set -uo pipefail
cd "$(dirname "$0")"

c_g(){ printf "\033[32m%s\033[0m\n" "$*"; }
c_y(){ printf "\033[33m%s\033[0m\n" "$*"; }
c_r(){ printf "\033[31m%s\033[0m\n" "$*"; }
hr(){ printf '─%.0s' {1..60}; echo; }

ARCH="$(uname -m)"; [ "$ARCH" = "x86_64" ] && ARCH=amd64; [ "$ARCH" = "aarch64" ] && ARCH=arm64
OS="$(uname -s)"
PM=""
if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
elif command -v brew >/dev/null 2>&1; then PM=brew
fi
SUDO=""; [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1 && SUDO=sudo
BIN=/usr/local/bin

# ── Danh mục công cụ: key|nhóm|mô tả|lệnh-kiểm-tra ──
declare -A GROUP_DESC=(
  [sast]="SAST — quét source code (semgrep, bandit)"
  [sca]="SCA — quét thư viện/CVE (trivy, pip-audit)"
  [secrets]="Secrets — lộ khoá/mật khẩu (gitleaks, detect-secrets)"
  [iac]="IaC — Terraform/K8s/Dockerfile (checkov, hadolint)"
  [container]="Container — quét image (grype)"
  [web]="Web/DAST — crawl + quét web (katana, nuclei)"
  [pentest]="Pentest Agent — công cụ tấn công (nmap, ffuf, sqlmap, seclists)"
  [ai]="AI local (tuỳ chọn) — Ollama"
)
ORDER=(sast sca secrets iac container web pentest ai)

pip_install(){ ".venv/bin/pip" install -q "$@" 2>/dev/null && c_g "  ✓ $*" || c_y "  ⚠ pip $* lỗi"; }
sys_install(){
  case "$PM" in
    apt) $SUDO apt-get install -y "$@" >/dev/null 2>&1 ;;
    dnf) $SUDO dnf install -y "$@" >/dev/null 2>&1 ;;
    yum) $SUDO yum install -y "$@" >/dev/null 2>&1 ;;
    brew) brew install "$@" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
dl_bin(){ # dl_bin <url> <name-in-archive|-> <out>
  local url="$1" name="$2" out="$3" tmp; tmp="$(mktemp -d)"
  curl -sL "$url" -o "$tmp/a" || { rm -rf "$tmp"; return 1; }
  case "$url" in
    *.zip) unzip -p "$tmp/a" "$name" > "$BIN/$out" ;;
    *.tar.gz|*.tgz) tar -xzf "$tmp/a" -C "$tmp" "$name" && $SUDO mv "$tmp/$name" "$BIN/$out" ;;
    *) $SUDO mv "$tmp/a" "$BIN/$out" ;;
  esac
  $SUDO chmod +x "$BIN/$out" 2>/dev/null; rm -rf "$tmp"
}

install_group(){
  case "$1" in
    sast)  pip_install semgrep bandit ;;
    sca)   pip_install pip-audit
           command -v trivy >/dev/null || { c_y "  … trivy"; curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b $BIN >/dev/null 2>&1 && c_g "  ✓ trivy" || c_y "  ⚠ trivy (xem aquasecurity/trivy)"; } ;;
    secrets) pip_install detect-secrets
           command -v gitleaks >/dev/null || c_y "  ⚠ gitleaks — tải binary tại github.com/gitleaks/gitleaks/releases" ;;
    iac)   pip_install checkov
           command -v hadolint >/dev/null || { $SUDO curl -sL "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-$(uname -s)-$(uname -m)" -o $BIN/hadolint 2>/dev/null && $SUDO chmod +x $BIN/hadolint && c_g "  ✓ hadolint" || c_y "  ⚠ hadolint"; } ;;
    container) command -v grype >/dev/null || { curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b $BIN >/dev/null 2>&1 && c_g "  ✓ grype" || c_y "  ⚠ grype"; } ;;
    web)   command -v katana >/dev/null || { dl_bin "https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_${ARCH}.zip" katana katana && c_g "  ✓ katana" || c_y "  ⚠ katana"; }
           command -v nuclei >/dev/null || { dl_bin "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.7/nuclei_3.4.7_linux_${ARCH}.zip" nuclei nuclei && c_g "  ✓ nuclei" && nuclei -update-templates -silent >/dev/null 2>&1 || c_y "  ⚠ nuclei"; } ;;
    pentest) sys_install nmap dnsutils sqlmap && c_g "  ✓ nmap/sqlmap" || c_y "  ⚠ nmap/sqlmap (cài qua $PM)"
           command -v ffuf >/dev/null || { dl_bin "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${ARCH}.tar.gz" ffuf ffuf && c_g "  ✓ ffuf" || c_y "  ⚠ ffuf"; }
           [ -d /usr/share/seclists ] || { $SUDO git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists >/dev/null 2>&1 && c_g "  ✓ seclists" || c_y "  ⚠ seclists (content_discovery cần wordlist)"; } ;;
    ai)    command -v ollama >/dev/null || { curl -fsSL https://ollama.com/install.sh | sh >/dev/null 2>&1 && c_g "  ✓ ollama (nhớ: ollama pull llama3.2)" || c_y "  ⚠ ollama — xem ollama.com"; } ;;
  esac
}

check_tools(){
  hr; c_g "Trạng thái công cụ:"
  for t in semgrep bandit trivy pip-audit gitleaks detect-secrets checkov hadolint grype katana nuclei nmap ffuf sqlmap ollama; do
    if command -v "$t" >/dev/null 2>&1; then printf "  \033[32m✓\033[0m %s\n" "$t"; else printf "  \033[31m✗\033[0m %s\n" "$t"; fi
  done; hr
}

# ── Parse args ──
MODE=""; TOOLS=""; RUN=1; INTERACTIVE=1; SKIP_ADMIN=0; ADMIN_EMAIL="${ADMIN_EMAIL:-}"
while [ $# -gt 0 ]; do case "$1" in
  --mode) MODE="$2"; INTERACTIVE=0; shift 2;;
  --tools) TOOLS="$2"; INTERACTIVE=0; shift 2;;
  --no-run) RUN=0; shift;;
  --admin-email) ADMIN_EMAIL="$2"; shift 2;;
  --admin-password) ADMIN_PASSWORD="$2"; export ADMIN_PASSWORD; shift 2;;
  --skip-admin) SKIP_ADMIN=1; shift;;
  --check) check_tools; exit 0;;
  *) shift;;
esac; done

clear 2>/dev/null || true
c_g "🛡️  VulnGuard — Cài đặt"; hr
echo "OS: $OS ($ARCH) · Package manager: ${PM:-không rõ}"

# ── Chọn Docker/Native ──
if [ -z "$MODE" ]; then
  echo ""; echo "Chọn cách chạy:"; echo "  1) Docker Compose (gọn, mọi tool đóng gói sẵn trong image)"
  echo "  2) Native (Python venv + tự chọn công cụ hệ thống)"
  read -rp "Lựa chọn [1]: " m; MODE=$([ "${m:-1}" = "2" ] && echo native || echo docker)
fi

if [ "$MODE" = "docker" ]; then
  command -v docker >/dev/null || { c_r "❌ Chưa có Docker. Cài Docker Desktop rồi chạy lại."; exit 1; }
  [ -f .env ] || { cp .env.example .env; c_y "Đã tạo .env — hãy sửa SCAN_WORKSPACE trỏ tới thư mục source."; }
  c_g "Build image (đã gồm toàn bộ scanner + nmap/nuclei/ffuf/sqlmap)…"
  docker compose build && { [ "$RUN" = 1 ] && docker compose up -d && c_g "✅ Chạy tại http://localhost:${VULNGUARD_PORT:-8080} — tạo ADMIN ở trang đăng nhập."; }
  exit 0
fi

# ── Native ──
command -v python3 >/dev/null || { c_r "❌ Cần Python 3.11+"; exit 1; }
# Env production (khớp run.sh) để bootstrap admin ghi đúng DB
[ -f .env ] && set -a && . ./.env && set +a || true
export DATABASE_URL="${DATABASE_URL:-sqlite:///$PWD/storage/db/vulnguard.db}"
export AI_CONFIG_FILE="${AI_CONFIG_FILE:-$PWD/storage/ai_config.json}"
export AUTH_ENABLED="${AUTH_ENABLED:-true}"; export APP_ENV="${APP_ENV:-production}"; export DEPLOY_MODE="${DEPLOY_MODE:-native}"
mkdir -p "$PWD/storage/db"
if [ ! -d .venv ]; then c_g "Tạo virtualenv + cài API deps…"; python3 -m venv .venv; .venv/bin/pip install -q --upgrade pip; fi
.venv/bin/pip install -q -r api/requirements.txt && c_g "✓ Python dependencies"

# ── Chọn nhóm công cụ ──
if [ -z "$TOOLS" ] && [ "$INTERACTIVE" = 1 ]; then
  echo ""; c_g "Chọn nhóm công cụ cần cài (quét thật cần các tool này; bỏ qua nếu chỉ xem UI/Document Review):"
  i=1; declare -A IDX
  for k in "${ORDER[@]}"; do echo "  $i) ${GROUP_DESC[$k]}"; IDX[$i]=$k; i=$((i+1)); done
  echo "  a) Tất cả    (trừ AI)        n) Không cài gì thêm"
  read -rp "Nhập số cách nhau bởi dấu cách (vd: 1 2 6 7), hoặc a/n [a]: " sel; sel="${sel:-a}"
  if [ "$sel" = "n" ]; then TOOLS=""
  elif [ "$sel" = "a" ]; then TOOLS="sast sca secrets iac container web pentest"
  else TOOLS=""; for n in $sel; do [ -n "${IDX[$n]:-}" ] && TOOLS="$TOOLS ${IDX[$n]}"; done; fi
fi

if [ -n "$TOOLS" ]; then
  hr; for g in $TOOLS; do c_g "▶ ${GROUP_DESC[$g]:-$g}"; install_group "$g"; done; hr
fi

[ -f .env ] || { [ -f .env.native.example ] && cp .env.native.example .env && c_y "Đã tạo .env (sửa nếu cần)."; }
check_tools

# ── Tạo tài khoản ADMIN + sinh mật khẩu (nếu chưa có user) ──
if [ "$SKIP_ADMIN" != "1" ]; then
  ADMIN_EMAIL="${ADMIN_EMAIL:-}"
  if [ -z "$ADMIN_EMAIL" ] && [ "$INTERACTIVE" = 1 ]; then
    read -rp "Email ADMIN [admin@vulnguard.local]: " ADMIN_EMAIL
  fi
  export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@vulnguard.local}"
  c_g "Tạo tài khoản ADMIN (sinh mật khẩu ngẫu nhiên nếu chưa có)…"
  .venv/bin/python -m scripts.bootstrap_admin "$ADMIN_EMAIL" || c_y "⚠ Không tạo được ADMIN tự động — tạo qua trang đăng nhập."
fi

if [ "$RUN" = 1 ]; then
  c_g "Khởi động production…"; exec bash run.sh
else
  c_g "✅ Cài xong. Chạy app: bash run.sh"
fi
