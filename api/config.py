from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",   # Bỏ qua các env var không khai báo trong model
    )

    database_url: str = "sqlite:////app/storage/db/vulnguard.db"
    # Default này chỉ dùng khi không có .env / env var OLLAMA_URL nào được set.
    # docker-compose.yml luôn set OLLAMA_URL=http://host.docker.internal:11434
    # (Ollama chạy trên host, không phải trong container) — khớp default ở đây
    # để tránh 2 giá trị khác nhau cho cùng 1 cấu hình.
    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "llama3.2"  # Phải khớp với OLLAMA_MODEL trong .env
    ollama_timeout: int = 120
    # Vision model — đọc/mô tả ảnh (sơ đồ) nhúng trong tài liệu .docx/.pdf.
    # Cần model hỗ trợ ảnh: ollama pull llama3.2-vision (hoặc llava, qwen2.5vl).
    ollama_vision_model: str = "llama3.2-vision"
    doc_max_images: int = 10  # số ảnh tối đa phân tích mỗi tài liệu (tránh quá chậm)
    # Coworker Host Service — service nhỏ chạy native trên host (giống Ollama),
    # cho phép tính năng Co-work đọc/sửa file & chạy lệnh ở folder ngoài Docker.
    # Xem coworker_host/app.py + coworker_host/run.sh
    coworker_url: str = "http://host.docker.internal:8765"
    coworker_timeout: int = 30
    max_scans_per_project: int = 5
    max_crawls_per_domain: int = 5   # rolling — giống max_scans_per_project, cho domain sitemap crawl
    block_severity_threshold: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"
    app_env: str = "production"
    # "docker" (default) hoặc "native" — native install set qua .env (DEPLOY_MODE=native)
    # Dùng để Web UI hiển thị hint scan path đúng (path container vs path thật trên host)
    deploy_mode: Literal["docker", "native"] = "docker"

    # ── SonarQube — SAST sâu, giảm false positive (tuỳ chọn) ──
    # Trỏ tới SonarQube server của bạn (bản nào cũng được), hoặc dùng service bundled
    # (docker compose --profile sonar).
    sonarqube_url: str = ""          # vd http://sonarqube:9000 (bundled) hoặc https://sonar.corp.vn
    sonarqube_token: str = ""        # token tạo trong Sonar (My Account → Security)
    sonarqube_timeout: int = 900

    # ── Auth ──
    # AUTH_ENABLED=false chỉ dành cho dev/local 1 người — production luôn bật.
    auth_enabled: bool = True
    # 1.9: feature flags — tắt để ẩn module ngoài ICP khỏi bản bán.
    feature_coworker: bool = True
    feature_docreview: bool = True
    # File Assistant chưa có UI (B-4) → mặc định tắt (D-8). Bật: FEATURE_FILE_ASSISTANT=true
    feature_file_assistant: bool = False
    # Secret ký JWT + mã hoá API key cloud AI. Để trống → tự sinh & lưu vào
    # <storage>/secret.key (chmod 600). Đặt cố định nếu chạy nhiều instance.
    vulnguard_secret_key: str = ""
    # L-2: setup token cho lần thiết lập đầu tiên. Trống → tự sinh vào <storage>/setup_token (0600) khi chưa có user.
    vulnguard_setup_token: str = ""
    session_ttl_hours: int = 12
    # Cookie Secure flag — bật khi chạy sau HTTPS reverse proxy
    cookie_secure: bool = False
    # Host header được chấp nhận (csv, vd "vulnguard.corp.vn"). Auth TẮT → luôn giới hạn loopback + danh sách này
    # (chặn DNS rebinding). Auth BẬT → chỉ kiểm tra khi danh sách không rỗng.
    allowed_hosts: str = ""
    # CORS: mặc định same-origin (không bật CORS). Liệt kê origin được phép (csv) nếu có client trình duyệt bên thứ ba.
    cors_allow_origins: str = ""
    # Swagger /docs, /redoc, /openapi.json (luôn yêu cầu đăng nhập khi auth bật). False → tắt hẳn.
    expose_api_docs: bool = True
    # SCM: chống SSRF qua base_url. http chỉ khi bật; dải private (RFC1918/ULA) cho GitLab on-prem mặc định cho phép.
    scm_allow_http: bool = False
    scm_allow_private_hosts: bool = True

    # ── Web scan (Nuclei) ──
    max_webscans_per_domain: int = 5
    nuclei_timeout_minutes: int = 60

    # ── Knowledge Base (DB tri thức lỗ hổng, kiểu Trivy DB) ──
    # Máy đã cài tự tải snapshot KB mới nhất từ URL manifest (GitHub Releases).
    # Để trống kb_manifest_url → tắt auto-update (chỉ import offline thủ công).
    kb_manifest_url: str = "https://github.com/datntpro/vulnguard/releases/download/kb-latest/kb-manifest.json"
    # Chữ ký Ed25519 manifest KB: có .sig thì LUÔN verify. Đặt true để từ chối manifest thiếu .sig
    # (mặc định false trong 1 release đầu để auto-update không gãy — xem docs/PR rollout).
    kb_require_signature: bool = False
    kb_max_manifest_age_days: int = 7      # manifest đã ký cũ hơn → cảnh báo freeze (stale)
    kb_auto_update: bool = True            # kiểm tra + tải bản mới hàng ngày
    kb_update_interval_hours: int = 24     # chu kỳ kiểm tra

    # ── Allow-list đường dẫn (M-3/H-1, D-7) ──
    # CSV các thư mục được phép scan. Rỗng → docker: /workspace; native: thư mục home.
    scan_allowed_roots: str = ""
    # CSV thư mục File Assistant được đọc. Rỗng → dùng như scan_allowed_roots.
    file_assistant_allowed_roots: str = ""

    # ── Giới hạn upload zip (M-5) ──
    upload_max_bytes: int = 300 * 1024 * 1024
    upload_max_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024
    upload_max_files: int = 50_000
    upload_max_ratio: int = 200
    # Giới hạn body cho mọi route POST/PUT/PATCH khác (docreview, knowledge import, logo…)
    body_max_bytes: int = 300 * 1024 * 1024

    @property
    def storage_dir(self) -> str:
        """Thư mục storage gốc — suy ra từ DATABASE_URL (…/storage/db/x.db → …/storage)."""
        import os
        db_path = self.database_url.replace("sqlite:////", "/").replace("sqlite:///", "")
        if os.path.isabs(db_path):
            return os.path.dirname(os.path.dirname(db_path))
        return os.path.abspath("storage")


settings = Settings()
