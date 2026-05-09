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

# ─────────────────────────────────────────────
# Python dependencies
# ─────────────────────────────────────────────
COPY api/requirements.txt .

# Bước 1: API dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Bước 2: Scanner Python packages
RUN pip install --no-cache-dir \
    semgrep \
    "bandit[toml]" \
    checkov \
    detect-secrets \
    pip-audit

# Bước 3: Re-install API packages để đảm bảo đúng version
RUN pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────
# Pre-cache Semgrep rules
# ─────────────────────────────────────────────
ENV SEMGREP_HOME=/root/.semgrep
RUN semgrep --config p/python --config p/security-audit --config p/owasp-top-ten \
    --metrics=off --dry-run /dev/null 2>/dev/null || true

# ─────────────────────────────────────────────
# Copy source code
# ─────────────────────────────────────────────
COPY api/ ./api/
COPY scanner/ ./scanner/
COPY web/ ./web/

RUN mkdir -p /app/storage/db /app/storage/reports

EXPOSE 8080

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
