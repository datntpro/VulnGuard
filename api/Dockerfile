# ─────────────────────────────────────────────
# VulnGuard — All-in-one Docker Image
# FastAPI + Scanner Tools (Semgrep, Trivy, Checkov, Gitleaks, ...)
# ─────────────────────────────────────────────

FROM python:3.11-slim

# Build arg — Docker tự inject: amd64 hoặc arm64
ARG TARGETARCH

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git unzip ca-certificates gnupg apt-transport-https \
    nmap dnsutils sqlmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─────────────────────────────────────────────
# Scanner Tools
# ─────────────────────────────────────────────

# 1. Trivy — via apt repo (ổn định hơn download script, tự resolve arch)
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor > /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/*

# 2. Gitleaks — arch-aware (amd64 / arm64)
RUN ARCH=${TARGETARCH:-amd64} \
    && if [ "$ARCH" = "arm64" ]; then GL_ARCH="arm64"; else GL_ARCH="x64"; fi \
    && curl -sL \
        "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_${GL_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# 3. Hadolint — arch-aware (x86_64 / arm64)
RUN ARCH=${TARGETARCH:-amd64} \
    && if [ "$ARCH" = "arm64" ]; then HL_ARCH="arm64"; else HL_ARCH="x86_64"; fi \
    && curl -sL \
        "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-${HL_ARCH}" \
        -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# 4. Grype — install script tự detect arch
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin \
    || echo "⚠ Grype install failed — skipping (non-critical)"

# 5. Katana — web crawler dùng để build sitemap/endpoint inventory cho domain
#    (feature "Domain Sitemap / WAF Baseline") — arch-aware (amd64 / arm64)
RUN ARCH=${TARGETARCH:-amd64} \
    && if [ "$ARCH" = "arm64" ]; then KT_ARCH="arm64"; else KT_ARCH="amd64"; fi \
    && curl -sL \
        "https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_${KT_ARCH}.zip" \
        -o /tmp/katana.zip \
    && unzip -p /tmp/katana.zip katana > /usr/local/bin/katana \
    && rm -f /tmp/katana.zip \
    && chmod +x /usr/local/bin/katana \
    || echo "⚠ Katana install failed — skipping (chỉ ảnh hưởng tính năng Domain Sitemap)"

# 6. Nuclei — web vulnerability scanner (template-based, ~10k+ templates CVE/misconfig/exposure)
#    Quét các URL mà Katana đã crawl. Template tải sẵn lúc build để chạy được offline.
ARG NUCLEI_VERSION=3.4.7
RUN ARCH=${TARGETARCH:-amd64} \
    && if [ "$ARCH" = "arm64" ]; then NU_ARCH="arm64"; else NU_ARCH="amd64"; fi \
    && curl -sL \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NU_ARCH}.zip" \
        -o /tmp/nuclei.zip \
    && unzip -p /tmp/nuclei.zip nuclei > /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && (nuclei -update-templates -silent || echo "⚠ Không tải được nuclei-templates lúc build — sẽ tải khi chạy lần đầu") \
    || echo "⚠ Nuclei install failed — skipping (chỉ ảnh hưởng tính năng Web Scan)"

# 7. ffuf — content discovery (Pentest Agent). Wordlist seclists cài kèm (tuỳ chọn).
ARG FFUF_VERSION=2.1.0
RUN ARCH=${TARGETARCH:-amd64} \
    && if [ "$ARCH" = "arm64" ]; then FF_ARCH="arm64"; else FF_ARCH="amd64"; fi \
    && curl -sL \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${FF_ARCH}.tar.gz" \
        -o /tmp/ffuf.tgz \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
    && rm -f /tmp/ffuf.tgz && chmod +x /usr/local/bin/ffuf \
    || echo "⚠ ffuf install failed — skipping (chỉ ảnh hưởng content_discovery của Pentest Agent)"

# 8. SonarScanner CLI (kèm JRE) — cho tính năng SonarQube (SAST sâu). Tuỳ chọn.
#    Chỉ hữu dụng khi SONARQUBE_URL/TOKEN được cấu hình (server bundled hoặc sẵn có).
ARG SONAR_SCANNER_VERSION=6.2.1.4610
RUN ARCH=${TARGETARCH:-amd64} \
    && if [ "$ARCH" = "arm64" ]; then SC_ARCH="aarch64"; else SC_ARCH="x64"; fi \
    && curl -sL \
        "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-${SC_ARCH}.zip" \
        -o /tmp/sonar.zip \
    && unzip -q /tmp/sonar.zip -d /opt \
    && ln -s /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-${SC_ARCH}/bin/sonar-scanner /usr/local/bin/sonar-scanner \
    && rm -f /tmp/sonar.zip \
    || echo "⚠ sonar-scanner install failed — skipping (chỉ ảnh hưởng tính năng SonarQube)"
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null \
    || echo "⚠ SecLists clone failed — content_discovery cần chỉ định wordlist thủ công"

# 9. Chromium headless + fonts — render báo cáo PDF đẹp server-side (/report?format=pdf).
#    Font Liberation/DejaVu phủ tiếng Việt; Noto Color Emoji cho badge 🔥/💀 trong report.
#    Nếu cài lỗi, ảnh vẫn build được và PDF đẹp tự fallback sang in từ trình duyệt.
RUN (apt-get update && apt-get install -y --no-install-recommends \
        chromium fonts-liberation fonts-dejavu fonts-noto-color-emoji \
     && rm -rf /var/lib/apt/lists/*) \
    || echo "⚠ Chromium install failed — PDF server-side sẽ fallback sang in trình duyệt"
ENV CHROMIUM_PATH=/usr/bin/chromium

# ─────────────────────────────────────────────
# Python dependencies
# ─────────────────────────────────────────────
COPY api/requirements.txt .

# Bước 1: API dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Bước 2: Scanner Python packages (semgrep nằm trong venv riêng bên dưới:
# cài chung site-packages làm xung đột opentelemetry với requirements.txt → ImportError → SAST im lặng 0 finding)
RUN pip install --no-cache-dir \
    "bandit[toml]" \
    checkov \
    detect-secrets \
    pip-audit

# Bước 3: Re-install API packages để đảm bảo đúng version
RUN pip install --no-cache-dir -r requirements.txt

# Bước 4: Semgrep trong venv cô lập (không chia sẻ dependency với API)
ARG SEMGREP_VERSION=1.136.0
RUN python -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && semgrep --version

# Smoke test: build FAIL nếu bất kỳ scanner lõi nào không khởi động được
RUN bandit --version && checkov --version && pip-audit --version \
 && trivy --version && gitleaks version

# ─────────────────────────────────────────────
# Người dùng không phải root (H4 — hardening). Cache của tool trỏ vào thư mục
# ghi-được của user để chạy non-root không lỗi quyền.
# ─────────────────────────────────────────────
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser
ENV HOME=/home/appuser \
    SEMGREP_HOME=/home/appuser/.semgrep \
    XDG_CACHE_HOME=/home/appuser/.cache \
    XDG_CONFIG_HOME=/home/appuser/.config \
    TRIVY_CACHE_DIR=/app/storage/.trivy-cache

# Pre-cache Semgrep rules (ghi vào SEMGREP_HOME mới). semgrep phải chạy được (hard check);
# riêng bước tải rules có thể thất bại khi build offline → cảnh báo hiển thị, không im lặng.
RUN semgrep --version \
 && (semgrep --config p/python --config p/security-audit --config p/owasp-top-ten \
     --metrics=off --dry-run /dev/null \
     || echo "⚠ semgrep rule pre-cache failed (offline build?)")

# ─────────────────────────────────────────────
# Copy source code
# ─────────────────────────────────────────────
COPY api/ ./api/
COPY scanner/ ./scanner/
COPY web/ ./web/

RUN mkdir -p /app/storage/db /app/storage/reports /app/storage/.trivy-cache \
    && chown -R appuser:appuser /app /home/appuser

USER appuser

EXPOSE 8080

# host 0.0.0.0 bên TRONG container là bình thường (bị cô lập); việc KHÔNG phơi ra
# ngoài host do docker-compose bind 127.0.0.1 đảm nhiệm.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
