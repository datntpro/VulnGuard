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

    # ── SonarQube (Community) — SAST sâu, giảm false positive (tuỳ chọn) ──
    # Trỏ tới server Sonar sẵn có, hoặc dùng service bundled (docker compose --profile sonar).
    sonarqube_url: str = ""          # vd http://sonarqube:9000 (bundled) hoặc https://sonar.corp.vn
    sonarqube_token: str = ""        # token tạo trong Sonar (My Account → Security)
    sonarqube_timeout: int = 900

    # ── Auth ──
    # AUTH_ENABLED=false chỉ dành cho dev/local 1 người — production luôn bật.
    auth_enabled: bool = True
    # 1.9: feature flags — tắt để ẩn module ngoài ICP khỏi bản bán.
    feature_coworker: bool = True
    feature_docreview: bool = True
    feature_file_assistant: bool = True
    # Secret ký JWT + mã hoá API key cloud AI. Để trống → tự sinh & lưu vào
    # <storage>/secret.key (chmod 600). Đặt cố định nếu chạy nhiều instance.
    vulnguard_secret_key: str = ""
    session_ttl_hours: int = 12
    # Cookie Secure flag — bật khi chạy sau HTTPS reverse proxy
    cookie_secure: bool = False

    # ── Web scan (Nuclei) ──
    max_webscans_per_domain: int = 5
    nuclei_timeout_minutes: int = 60

    # ── Knowledge Base (DB tri thức lỗ hổng, kiểu Trivy DB) ──
    # Máy đã cài tự tải snapshot KB mới nhất từ URL manifest (GitHub Releases).
    # Để trống kb_manifest_url → tắt auto-update (chỉ import offline thủ công).
    kb_manifest_url: str = "https://github.com/datntpro/vulnguard/releases/download/kb-latest/kb-manifest.json"
    kb_auto_update: bool = True            # kiểm tra + tải bản mới hàng ngày
    kb_update_interval_hours: int = 24     # chu kỳ kiểm tra

    @property
    def storage_dir(self) -> str:
        """Thư mục storage gốc — suy ra từ DATABASE_URL (…/storage/db/x.db → …/storage)."""
        import os
        db_path = self.database_url.replace("sqlite:////", "/").replace("sqlite:///", "")
        if os.path.isabs(db_path):
            return os.path.dirname(os.path.dirname(db_path))
        return os.path.abspath("storage")


settings = Settings()
