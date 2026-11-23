# VulnGuard Wiki

**VulnGuard** — nền tảng DevSecOps *local-first*: quét lỗ hổng mã nguồn · web · tài liệu · pentest tự động · quản lý tài sản & rủi ro theo ngữ cảnh. Ở chế độ **local-only**, dữ liệu quét ở lại máy bạn; AI đám mây là tùy chọn (opt-in).

## Bắt đầu nhanh
```bash
git clone https://github.com/datntpro/VulnGuard.git && cd VulnGuard
bash setup.sh      # cài .venv + scanner (Windows: .\setup.ps1)
bash run.sh        # mở http://localhost:8080 (Windows: .\run.ps1)
```
Hoặc Docker: `docker compose up -d --build`. Lần đầu tạo tài khoản ADMIN ngay trên trang đăng nhập.

## Mục lục
- **[Installation](Installation)** — cài đặt native / Docker / Windows, yêu cầu hệ thống.
- **[Configuration](Configuration)** — biến môi trường, AI providers, Ollama, SonarQube, SMTP, feature flags.
- **[Features](Features)** — danh sách tính năng theo nhóm.
- **[Security & Data Flow](Security-and-Data-Flow)** — mô hình bảo mật, auth/RBAC, xác minh sở hữu, dữ liệu nào rời máy.
- **[Scanning & Triage](Scanning-and-Triage)** — luồng quét, trạng thái triage (Checkmarx-style), lịch sử & so sánh scan.
- **[SCM Integration](SCM-Integration)** — kết nối GitHub/GitLab, quét theo lịch, gửi báo cáo tự động.
- **[Compliance](Compliance)** — ánh xạ OWASP Top 10 / ISO 27001 / TCVN 11930 / PCI-DSS, SARIF.
- **[Pentest Agent](Pentest-Agent)** — agent pentest, scope gate, phê duyệt, tách quyền.
- **[Troubleshooting](Troubleshooting)** — lỗi thường gặp (cổng 8080, Docker image cũ, tool bị bỏ qua…).

## Kiến trúc tóm tắt
- **Backend**: Python + FastAPI + SQLite. Scanner chạy song song, dedup theo fingerprint.
- **Frontend**: SPA vanilla-JS (`web/index.html`), served bởi FastAPI.
- **Scanner tích hợp**: semgrep, bandit, trivy, pip-audit, gitleaks, detect-secrets, checkov, hadolint, grype, nuclei, (tùy chọn) SonarQube.
- **AI**: Ollama (local) hoặc cloud (Claude API / Amazon Bedrock / OpenAI / OpenRouter) — opt-in, có redaction.

## Giấy phép
AGPL-3.0 (Community) + tùy chọn thương mại (Pro) — xem `LICENSE`, `COMMERCIAL-LICENSE.md`, `EULA.md`.
