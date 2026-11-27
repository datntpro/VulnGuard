# ─────────────────────────────────────────────
# VulnGuard — All-in-one Docker Image
# FastAPI + Scanner Tools (Semgrep, Trivy, Checkov, Gitleaks, ...)
# ─────────────────────────────────────────────

FROM python:3.11-slim

# Build arg — Docker tự inject: amd64 hoặc arm64
ARG TARGETARCH

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git unzip ca-certificates \
    nmap dnsutils sqlmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ─────────────────────────────────────────────
# Scanner Tools (L-5: mọi binary tải về đều PIN phiên bản + kiểm sha256 theo kiến trúc)
# ─────────────────────────────────────────────
# Cập nhật phiên bản: đổi *_VERSION và 2 giá trị *_SHA256_* (lấy từ file checksums chính thức
# của release). sha256 sai → bước build lỗi (tool lõi) hoặc bị bỏ qua (tool tuỳ chọn) —
# KHÔNG BAO GIỜ cài binary chưa xác minh.
#
# Tool LÕI (trivy, gitleaks, grype, hadolint): lỗi → build FAIL (không có "|| echo").
# Tool TUỲ CHỌN (katana, nuclei, ffuf, sonar-scanner, SecLists): lỗi → cảnh báo và bỏ qua.

# 1. Trivy — release tarball + sha256 (thay cho apt repo không pin được phiên bản)
ARG TRIVY_VERSION=0.76.2
ARG TRIVY_SHA256_AMD64=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
ARG TRIVY_SHA256_ARM64=ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=ARM64; SUM="${TRIVY_SHA256_ARM64}"; else A=64bit; SUM="${TRIVY_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${A}.tar.gz" -o /tmp/trivy.tgz; \
    echo "${SUM}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tgz; chmod +x /usr/local/bin/trivy

# 2. Gitleaks
ARG GITLEAKS_VERSION=8.18.4
ARG GITLEAKS_SHA256_AMD64=ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d
ARG GITLEAKS_SHA256_ARM64=bf5f7f466ebfade1296c8bd32cf7d3f592c2aa78836aa9980ffbe2cadca7a861
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=arm64; SUM="${GITLEAKS_SHA256_ARM64}"; else A=x64; SUM="${GITLEAKS_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${A}.tar.gz" -o /tmp/gitleaks.tgz; \
    echo "${SUM}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tgz; chmod +x /usr/local/bin/gitleaks

# 3. Hadolint
ARG HADOLINT_VERSION=2.12.0
ARG HADOLINT_SHA256_AMD64=56de6d5e5ec427e17b74fa48d51271c7fc0d61244bf5c90e828aab8362d55010
ARG HADOLINT_SHA256_ARM64=5798551bf19f33951881f15eb238f90aef023f11e7ec7e9f4c37961cb87c5df6
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=arm64; SUM="${HADOLINT_SHA256_ARM64}"; else A=x86_64; SUM="${HADOLINT_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${A}" -o /usr/local/bin/hadolint; \
    echo "${SUM}  /usr/local/bin/hadolint" | sha256sum -c -; \
    chmod +x /usr/local/bin/hadolint

# 4. Grype — release tarball + sha256 (trước đây: curl main/install.sh | sh, không pin, không kiểm)
ARG GRYPE_VERSION=0.122.1
ARG GRYPE_SHA256_AMD64=f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538
ARG GRYPE_SHA256_ARM64=819e5be3d9516432fedb7b6b56df7306c3a16607606dfc05826eefbb00e471da
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=arm64; SUM="${GRYPE_SHA256_ARM64}"; else A=amd64; SUM="${GRYPE_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${A}.tar.gz" -o /tmp/grype.tgz; \
    echo "${SUM}  /tmp/grype.tgz" | sha256sum -c -; \
    tar -xzf /tmp/grype.tgz -C /usr/local/bin grype; \
    rm -f /tmp/grype.tgz; chmod +x /usr/local/bin/grype

# 5. Katana — web crawler (Domain Sitemap / WAF Baseline). TUỲ CHỌN.
ARG KATANA_VERSION=1.5.0
ARG KATANA_SHA256_AMD64=592890e5febaf5706d0a962d96299512418d6eccce6388cf1600e1f078ed359d
ARG KATANA_SHA256_ARM64=ca03709887bbf23b2110d48bbf8aeacc5cb0915c8dda0f035dc79a53bcfd68e4
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=arm64; SUM="${KATANA_SHA256_ARM64}"; else A=amd64; SUM="${KATANA_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${A}.zip" -o /tmp/katana.zip \
    && echo "${SUM}  /tmp/katana.zip" | sha256sum -c - \
    && unzip -p /tmp/katana.zip katana > /usr/local/bin/katana \
    && chmod +x /usr/local/bin/katana; \
    rm -f /tmp/katana.zip; \
    [ -x /usr/local/bin/katana ] || echo "⚠ Katana install failed/unverified — skipping (chỉ ảnh hưởng tính năng Domain Sitemap)"

# 6. Nuclei — web vulnerability scanner (template-based). TUỲ CHỌN.
#    Template tải sẵn lúc build để chạy được offline.
ARG NUCLEI_VERSION=3.4.7
ARG NUCLEI_SHA256_AMD64=1eb0c78ab15c1a271ae4cc86c5d08cb386cda89e69ecb0cd1a4356da8abdf0dd
ARG NUCLEI_SHA256_ARM64=5b46e7bde6b79a5bf0697d002139630e9f7f34dcb3ab95fc7cb980983d9cdb89
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=arm64; SUM="${NUCLEI_SHA256_ARM64}"; else A=amd64; SUM="${NUCLEI_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${A}.zip" -o /tmp/nuclei.zip \
    && echo "${SUM}  /tmp/nuclei.zip" | sha256sum -c - \
    && unzip -p /tmp/nuclei.zip nuclei > /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && (nuclei -update-templates -silent || echo "⚠ Không tải được nuclei-templates lúc build — sẽ tải khi chạy lần đầu"); \
    rm -f /tmp/nuclei.zip; \
    [ -x /usr/local/bin/nuclei ] || echo "⚠ Nuclei install failed/unverified — skipping (chỉ ảnh hưởng tính năng Web Scan)"

# 7. ffuf — content discovery (Pentest Agent). TUỲ CHỌN.
ARG FFUF_VERSION=2.1.0
ARG FFUF_SHA256_AMD64=fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5
ARG FFUF_SHA256_ARM64=6ae920d09d5202762fca21967a460c6fb88135bdfa806bee4d3d2c430dcedeea
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then A=arm64; SUM="${FFUF_SHA256_ARM64}"; else A=amd64; SUM="${FFUF_SHA256_AMD64}"; fi; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${A}.tar.gz" -o /tmp/ffuf.tgz \
    && echo "${SUM}  /tmp/ffuf.tgz" | sha256sum -c - \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf; \
    rm -f /tmp/ffuf.tgz; \
    [ -x /usr/local/bin/ffuf ] || echo "⚠ ffuf install failed/unverified — skipping (chỉ ảnh hưởng content_discovery của Pentest Agent)"

# 8. SonarScanner CLI (kèm JRE) — cho tính năng SonarQube (SAST sâu). TUỲ CHỌN.
ARG SONAR_SCANNER_VERSION=6.2.1.4610
ARG SONAR_SHA256_AMD64=0b8a3049f0bd5de7abc1582c78c233960d3d4ed7cc983a1d1635e8552f8bb439
ARG SONAR_SHA256_ARM64=f67819e7a52ed4c28b541baa5bca0621446314de148f889d7d2d7ff239808f0c
RUN set -eu; \
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then SC_ARCH=aarch64; SUM="${SONAR_SHA256_ARM64}"; else SC_ARCH=x64; SUM="${SONAR_SHA256_AMD64}"; fi; \
    curl -fsSL "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-${SC_ARCH}.zip" -o /tmp/sonar.zip \
    && echo "${SUM}  /tmp/sonar.zip" | sha256sum -c - \
    && unzip -q /tmp/sonar.zip -d /opt \
    && ln -s /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-${SC_ARCH}/bin/sonar-scanner /usr/local/bin/sonar-scanner; \
    rm -f /tmp/sonar.zip; \
    [ -x /usr/local/bin/sonar-scanner ] || echo "⚠ sonar-scanner install failed/unverified — skipping (chỉ ảnh hưởng tính năng SonarQube)"

# SecLists — pin theo TAG (không clone HEAD). TUỲ CHỌN.
ARG SECLISTS_TAG=2026.2
RUN git clone --depth 1 --branch "${SECLISTS_TAG}" https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null \
    || echo "⚠ SecLists clone failed — content_discovery cần chỉ định wordlist thủ công"

# 9. (PDF PR-5) Không còn cài font hệ thống: engine Typst chỉ dùng font đóng gói trong scanner/pdf/templates/fonts.
#    KHÔNG cài Chromium trong ảnh API (PR-0: gỡ renderer PDF SSRF/LFI).

# ─────────────────────────────────────────────
# Python dependencies
# ─────────────────────────────────────────────
# B-6: lockfile có hash (api/requirements.txt, sinh từ requirements.in) — cài MỘT lần, đúng
# phiên bản, mọi gói đều kiểm hash. Không còn bước "cài lại cho đúng version".
COPY api/requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Scanner CLI: mỗi tool một venv riêng với lockfile pin trong docker/scanners/ → không chia sẻ
# dependency với app (nguyên nhân gốc N-4: xung đột opentelemetry làm semgrep im lặng 0 finding).
# detect-secrets nằm trong env của app vì được import như thư viện.
COPY docker/scanners/ /tmp/scanners/
RUN set -eu; for t in semgrep bandit checkov pip-audit; do \
        python -m venv "/opt/tools/$t" \
        && "/opt/tools/$t/bin/pip" install --no-cache-dir --require-hashes -r "/tmp/scanners/$t.txt" \
        && ln -s "/opt/tools/$t/bin/$t" "/usr/local/bin/$t"; \
    done \
    && rm -rf /tmp/scanners

# Smoke test: build FAIL nếu bất kỳ scanner lõi nào không khởi động được
RUN semgrep --version && bandit --version && checkov --version && pip-audit --version \
 && trivy --version && gitleaks version && grype version && hadolint --version \
 && pip check

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

# Semgrep phải chạy được (venv sau khi đã đặt HOME/SEMGREP_HOME) (hard check, build FAIL nếu hỏng).
# Không pre-cache rule registry: semgrep không giữ lại config registry giữa các lần chạy,
# nên scan online tải rule khi chạy; bundled rules (scanner/rules) luôn dùng được offline.
RUN semgrep --version

# ─────────────────────────────────────────────
# Copy source code
# ─────────────────────────────────────────────
COPY api/ ./api/
COPY scanner/ ./scanner/
COPY web/ ./web/
COPY api/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /app/storage/db /app/storage/reports /app/storage/.trivy-cache \
    && chown -R appuser:appuser /app /home/appuser

USER appuser

# PDF (Typst) self-test: build FAIL nếu wheel typst/font/worker/sandbox hỏng (amd64 + arm64).
# Render 1 trang tiếng Việt trong worker đã siết, kiểm font nhúng và chặn @preview (không mạng).
# Không dùng `python -I`: -I bỏ cwd khỏi sys.path nên không import được scanner.* (WORKDIR=/app).
RUN python -m scanner.pdf.selftest

EXPOSE 8080

# host 0.0.0.0 bên TRONG container là bình thường (bị cô lập); việc KHÔNG phơi ra
# ngoài host do docker-compose bind 127.0.0.1 đảm nhiệm.
# Chỉ tin X-Forwarded-For từ các IP này (uvicorn đọc FORWARDED_ALLOW_IPS). Mặc định = chỉ loopback,
# tức KHÔNG tin header do client gửi (chống giả IP để né rate-limit). Nếu đặt reverse proxy trước app,
# đặt FORWARDED_ALLOW_IPS=<ip proxy> trong .env.
ENV FORWARDED_ALLOW_IPS=127.0.0.1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# --workers 1: trạng thái (khoá scan, proxy, lockout, scheduler) nằm trong bộ nhớ tiến trình — D-14.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
