# 🛡️ VulnGuard — Local DevSecOps Security Scanner

**VulnGuard** là công cụ scan bảo mật chạy hoàn toàn local, tích hợp AI phân tích (Ollama), hỗ trợ đầy đủ pipeline DevSecOps — từ scan code đến tạo báo cáo bảo mật tiếng Việt.

---

## 🚀 Quick Start

### Yêu cầu hệ thống

| | Tối thiểu | Khuyến nghị |
|---|---|---|
| **Docker** | v24+ với Compose v2 | Docker Desktop |
| **RAM** | 8 GB | 16 GB (cho AI model) |
| **Disk** | 10 GB | 20 GB |
| **OS** | macOS, Linux, Windows (WSL2) | macOS / Ubuntu |
| **Ollama** | Cài trên máy host (không cần Docker) | |

### Cài đặt Ollama (chạy trên máy host, không phải trong Docker)

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Pull AI model (chọn 1):
ollama pull llama3.2          # Recommended (4GB, cân bằng tốt)
ollama pull deepseek-coder:6.7b  # Tốt hơn cho code analysis (8GB RAM)
ollama pull phi3:mini          # Máy yếu <8GB RAM
```

### Khởi động VulnGuard

```bash
# 1. Clone / Giải nén project
cd VulnGuard

# 2. Cấu hình
cp .env.example .env
# Mở .env, sửa SCAN_WORKSPACE trỏ đến thư mục chứa source code:
#   SCAN_WORKSPACE=/home/user/projects    (Linux/macOS)
#   SCAN_WORKSPACE=C:/Users/user/projects (Windows WSL2)

# 3. Build và khởi động (lần đầu ~5-15 phút)
docker compose build
docker compose up -d

# 4. Mở trình duyệt
open http://localhost:8080
```

### Scan source code

```bash
# Bước 1: Copy source code vào workspace
cp -r /path/to/your/project ~/vulnguard-workspace/my-project

# Bước 2: Trong Web UI:
#   → Tạo Project → Trigger Scan → Nhập path: /workspace/my-project
```

---

## 🤖 AI Analysis (Ollama)

Ollama chạy trực tiếp trên máy host — **không gửi data ra ngoài internet**.

| Model | RAM | Chất lượng | Ghi chú |
|---|---|---|---|
| `llama3.2` | ~4 GB | ⭐⭐⭐⭐ | **Mặc định** — cân bằng tốc độ/chất lượng |
| `deepseek-coder:6.7b` | ~8 GB | ⭐⭐⭐⭐⭐ | Tốt nhất cho phân tích code |
| `codellama:7b` | ~6 GB | ⭐⭐⭐ | Thay thế tốt |
| `phi3:mini` | ~3 GB | ⭐⭐ | Máy yếu, RAM thấp |

Đổi model: vào **Settings → AI Model** trong Web UI, hoặc sửa `OLLAMA_MODEL` trong `.env`.

---

## 🛠️ Scanner Tools tích hợp

| Tool | Loại | Ngôn ngữ / Scope |
|---|---|---|
| **Semgrep** | SAST | Python, JS/TS, Java, Go, C/C++, Ruby... |
| **Bandit** | SAST | Python chuyên sâu |
| **Trivy** | SCA + IaC + Container | Multi-ecosystem (npm, pip, Maven, Go...) |
| **pip-audit** | SCA | Python dependencies (PyPI Advisory DB + OSV) |
| **Checkov** | IaC | Terraform, CloudFormation, K8s, Dockerfile, Ansible |
| **Hadolint** | IaC | Dockerfile linter |
| **Grype** | Container | Anchore CVE scanner cho container images |
| **Gitleaks** | Secrets | API keys, tokens, credentials trong code/git |
| **detect-secrets** | Secrets | Entropy analysis + keyword detection |

> Tất cả tools có thể **bật/tắt riêng lẻ** trong Settings → Scanner Tools.

---

## 📊 Tính năng chính

### 🔍 Scan Engine
- Chạy tất cả scanners **song song** (async) — tiết kiệm thời gian
- **Live progress**: Xem từng tool đang chạy, kết quả realtime
- Deduplication tự động theo fingerprint
- Hỗ trợ: SAST, SCA, IaC, Container, Secrets
- Path validation: Báo lỗi rõ nếu đường dẫn không tồn tại

### 🤖 AI Analysis
- **False Positive detection**: % likelihood kèm lý do cụ thể
- **Exploitability Public/Private**: Đánh giá rủi ro theo môi trường
- **Giải thích tiếng Việt**: Developer dễ hiểu, không cần đọc CVE gốc
- **Hướng dẫn fix chi tiết**: Kèm code snippet, tên file, số dòng

### 📄 Báo cáo AI (HTML)
- Tạo báo cáo HTML hoàn chỉnh sau scan
- **Dedup cross-tool**: Cùng vuln tìm thấy bởi nhiều tools → gộp lại
- **Group theo thành phần**: Package (SCA), Rule (SAST), Secret type, IaC check
- Bảng tổng hợp: Thành phần · Số lỗi · Mức độ · Phát hiện bởi tool nào · Nhận định AI
- Chi tiết: File path + số dòng + code snippet + hướng dẫn fix
- Nút **Tải xuống .html** (gửi email / lưu trữ) và **In / Xuất PDF**

### 🔐 Vulnerability Management
- Lưu tối đa **5 scans** mỗi project (rolling)
- Track trạng thái: `OPEN` → `ACCEPTED` / `FALSE_POSITIVE` / `FIXED`
- **Waiver system**: Accept risk với approver name + lý do + ngày hết hạn

### ✅ Approve Flow
- **Severity threshold**: Block approve nếu còn OPEN vuln ≥ threshold
- **Approve Check**: Kiểm tra nhanh trước khi deploy
- **Scan Compare**: Xem diff — vulns mới / đã fix / còn tồn tại giữa 2 scans

### ⚙️ Settings
- **Scanner Tools**: Kiểm tra install status + version, bật/tắt từng tool
- **AI Model**: Quản lý Ollama models, đổi model active
- Export: JSON, CSV, HTML report

---

## 📁 Cấu trúc Project

```
VulnGuard/
├── docker-compose.yml          # Container orchestration
├── .env                        # Cấu hình (SCAN_WORKSPACE, OLLAMA_MODEL...)
├── .env.example                # Cấu hình mẫu
├── api/
│   ├── Dockerfile              # All-in-one: API + tất cả Scanner tools
│   ├── requirements.txt        # Python deps cho API
│   ├── config.py               # App settings (pydantic-settings)
│   ├── database.py             # SQLite connection
│   ├── main.py                 # FastAPI app entry point
│   ├── models.py               # DB models: Project, Scan, Vulnerability, Waiver
│   ├── schemas.py              # Pydantic schemas
│   └── routes/
│       ├── projects.py         # CRUD projects
│       ├── scans.py            # Trigger scan, live progress, export
│       ├── vulns.py            # Vulnerability management, waivers
│       ├── compare.py          # Scan comparison, approve check
│       ├── report.py           # AI HTML report generator
│       ├── settings.py         # Scanner health check, enable/disable
│       └── ollama.py           # Ollama model management
├── scanner/
│   ├── orchestrator.py         # Chạy song song, live callback, dedup
│   ├── ai_analyzer.py          # Ollama integration, tiếng Việt
│   └── scanners/
│       ├── base.py             # BaseScanner abstract class
│       ├── sast.py             # Semgrep (bundled rules + online), Bandit
│       ├── sca.py              # Trivy SCA, pip-audit
│       ├── container.py        # Trivy container, Grype
│       ├── iac.py              # Checkov, TrivyIaC, Hadolint
│       ├── secrets.py          # Gitleaks, detect-secrets
│       └── rules/
│           └── python-security.yaml  # Bundled Semgrep rules (offline)
├── web/
│   └── index.html              # Single-page Web Dashboard
└── storage/                    # Persistent data (Docker volume)
    ├── db/                     # SQLite database
    └── scanner_config.json     # Scanner enable/disable config
```

---

## 📡 API Endpoints

```
# Projects
GET    /api/projects                           Danh sách projects
POST   /api/projects                           Tạo project
DELETE /api/projects/{id}                      Xóa project

# Scans
POST   /api/projects/{id}/scans                Trigger scan mới
GET    /api/projects/{id}/scans                Danh sách scans
GET    /api/projects/scans/{id}                Chi tiết scan
GET    /api/projects/scans/{id}/progress       Live progress (poll 2s)
GET    /api/projects/scans/{id}/vulns          Danh sách vulnerabilities
GET    /api/projects/scans/{id}/export         Export JSON hoặc CSV

# AI Report
GET    /api/scans/{id}/report                  Xem báo cáo HTML
GET    /api/scans/{id}/report?download=true    Tải xuống file .html

# Vulnerability Management
PATCH  /api/vulns/{id}/status                  Đổi trạng thái vuln
POST   /api/vulns/{id}/waiver                  Tạo waiver (accept risk)
DELETE /api/vulns/{id}/waiver                  Xóa waiver

# Approve & Compare
GET    /api/projects/{id}/approve-check        Kiểm tra approve
GET    /api/projects/{id}/compare              So sánh 2 scans

# Settings
GET    /api/settings/scanners                  Health check tất cả tools
PUT    /api/settings/scanners                  Lưu enable/disable config

# Ollama
GET    /api/ollama/health                      Kiểm tra Ollama
GET    /api/ollama/models                      Danh sách models
POST   /api/ollama/pull                        Pull model mới
PUT    /api/ollama/active-model                Đổi model active

# Swagger UI: http://localhost:8080/docs
```

---

## 🔄 Workflow điển hình

```
1. Developer push code lên nhánh mới
2. Security Approver mở VulnGuard → Tạo Project (nếu chưa có)
3. Copy source code vào SCAN_WORKSPACE
4. Trigger Scan → chọn scan types → theo dõi live progress
5. Chờ AI Analysis hoàn tất (tự động sau scan)
6. Review vulnerabilities:
   ├── CRITICAL/HIGH → ưu tiên fix
   ├── Đánh dấu False Positive (AI hỗ trợ đánh giá)
   └── Accept Risk → tạo Waiver (ghi rõ lý do + người duyệt + ngày hết hạn)
7. Tạo Báo Cáo AI → gửi file .html cho dev team fix
8. Dev fix xong → Scan lại → Compare để xác nhận
9. Chạy Approve Check → phải ra "APPROVED" → Deploy
```

---

## ⚙️ Cấu hình (.env)

```bash
# Port Web UI
VULNGUARD_PORT=8080

# Thư mục source code trên máy host (mount vào /workspace trong container)
SCAN_WORKSPACE=/Users/yourname/vulnguard-workspace

# Docker socket (macOS Docker Desktop)
DOCKER_SOCK=/Users/yourname/.docker/run/docker.sock
# Docker socket (Linux)
# DOCKER_SOCK=/var/run/docker.sock

# Ollama
OLLAMA_MODEL=llama3.2        # Model đang dùng (phải đã ollama pull)
OLLAMA_TIMEOUT=120            # Timeout AI analysis (giây)

# Scan limits
MAX_SCANS_PER_PROJECT=5       # Rolling: tự xóa scan cũ nhất
BLOCK_SEVERITY_THRESHOLD=HIGH # Block approve nếu còn OPEN >= mức này
```

---

## 🔒 Bảo mật & Privacy

- VulnGuard và Ollama chạy **hoàn toàn local** — không gửi code hay kết quả ra ngoài
- Không cần account, không cần API key nào
- Database SQLite lưu tại `./storage/db/` — tự backup khi cần
- Docker socket mount chỉ dùng để scan container images

---

## 🐛 Troubleshooting

**Scan path không tồn tại:**
```
Hãy đảm bảo SCAN_WORKSPACE trong .env trỏ đúng thư mục,
rồi dùng path /workspace/<tên-folder> trong UI.
```

**AI Analysis không chạy / báo "không kết nối":**
```bash
# Kiểm tra Ollama đang chạy
ollama list
curl http://localhost:11434/api/tags

# Nếu chưa chạy
ollama serve
```

**Rebuild sau khi cập nhật:**
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

**Xem logs:**
```bash
docker compose logs -f vulnguard
```
