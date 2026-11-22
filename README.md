# 🛡️ VulnGuard — Local DevSecOps Security Scanner

**VulnGuard** là công cụ scan bảo mật chạy hoàn toàn local, tích hợp AI phân tích (Ollama), hỗ trợ đầy đủ pipeline DevSecOps — từ scan code đến tạo báo cáo bảo mật tiếng Việt.

> Powered by **[1VISION](https://1vision.work)**

> 🐧 **Máy không cài được Docker?** Xem hướng dẫn cài đặt native (Python venv + systemd):
> [docs/NATIVE_INSTALL.md](docs/NATIVE_INSTALL.md)

---

## ✨ Mới (bản này)

VulnGuard không còn chỉ quét code — nay là nền tảng bảo mật hợp nhất, vẫn chạy local:

- **🔐 Đăng nhập & phân quyền (RBAC)** — ADMIN / ANALYST / VIEWER, session cookie, tạo ADMIN đầu tiên khi mở app.
- **🤖 AI đám mây giảm false positive** — ngoài Ollama local, tích hợp **Claude API** (API key / Workload Identity Federation / environment) và **Amazon Bedrock** (IAM — nền tảng Kiro dùng). 3 chế độ: local-only / hybrid / cloud-only. Xem Settings → AI Provider.
- **🌐 Web scan (Nuclei)** — quét lỗ hổng web trên các URL Katana đã crawl.
- **🎯 Pentest Agent (tự động, có kiểm soát)** — vòng lặp planner/worker do Claude lái, chạy công cụ thật (nmap/nuclei/ffuf/sqlmap), **scope gate + risk gate + approval + budget + audit**, chuỗi tấn công (todolist), chạy song song. Gắn **bằng chứng** request/response (recording **MITM proxy** có CA). → `docs/PENTEST_AGENT.md`
- **🗂️ Asset inventory + risk scoring theo ngữ cảnh** — điểm rủi ro kiểu Tenable VPR/Nexpose: `CVSS × EPSS × KEV × độ quan trọng × mức phơi bày`, cộng khi có cảnh báo EDR đang hoạt động.
- **🔌 Connector XDR/EDR/NAC + MCP** — Trellix XDR, Trend Micro Vision One, FortiNAC (secret mã hoá); MCP server expose dữ liệu cho agent/Claude Desktop. → `docs/CONNECTORS_MCP.md`
- **📊 Dashboard rủi ro toàn hệ thống** — gom code/web/pentest/asset thành một điểm tư thế rủi ro + top rủi ro + độ phủ.

> ⚠️ Pentest Agent chỉ dùng cho tài sản **bạn sở hữu hoặc được uỷ quyền bằng văn bản**. Mọi hành động phá huỷ đều qua người duyệt.

---

## 🚀 Quick Start

### Cài đặt — chạy được trên **macOS · Linux · Windows**

Trình cài đặt chung viết bằng Python (`scripts/setup.py`) — chọn Docker hoặc Native, tự chọn công cụ, **tự sinh mật khẩu ADMIN**, rồi chạy production tại **http://localhost:8080**.

| OS | Lệnh |
|---|---|
| **macOS / Linux** | `bash setup.sh` |
| **Windows** (PowerShell) | `powershell -ExecutionPolicy Bypass -File setup.ps1` |
| **Mọi OS** (có Python) | `python3 scripts/setup.py` (Windows: `python scripts\setup.py`) |
| **Mọi OS** (Docker) | `bash setup.sh --docker`  ·  hoặc trực tiếp `docker compose up -d --build` |

Các cờ dùng chung (không tương tác):

| Lệnh | Tác dụng |
|---|---|
| `... --check` | Liệt kê công cụ đã/chưa cài |
| `... --tools "sast sca web pentest" --no-run` | Cài không tương tác, không chạy |
| `... --docker` | Dùng Docker Compose (image gồm sẵn mọi tool) |
| `... --admin-email you@corp.vn` | Đặt email ADMIN (vẫn tự sinh mật khẩu) |
| `bash run.sh` / `.\run.ps1` | Chạy lại **production** (đã cài) |
| `bash run_demo.sh` | Chạy **demo** có sẵn dữ liệu mẫu |

**Khuyến nghị theo OS:**
- **Windows**: cách gọn & đủ nhất là **Docker Desktop** (`--docker`) — image Linux chạy đủ mọi scanner. Bản Native chạy tốt phần lõi + nuclei/katana/ffuf/trivy; riêng **semgrep (SAST) cần Docker/WSL** trên Windows.
- **macOS**: nên cài **Homebrew** để `setup.sh` cài công cụ gọn hơn (nmap/sqlmap/ffuf…). Ollama tải tại ollama.com/download.
- **Linux**: `setup.sh` tự dùng `apt/dnf/yum`.

**Yêu cầu:** Python 3.11+ (cho Native) hoặc Docker. Công cụ quét chỉ cần khi quét thật — có thể bỏ qua nếu chỉ dùng UI/Document Review.

> Bản **demo**: `demo@vulnguard.local` / `VulnGuardDemo!` (dữ liệu mẫu, không quét thật).

<details><summary>Cách thủ công (Docker Compose)</summary>



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
</details>

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

## 🧑‍💻 Co-work (AI sửa code)

Tính năng AI coding assistant — đọc/sửa file, sinh diff đề xuất bằng Ollama, chạy lệnh trong sandbox. Khác với Scan Engine (chỉ đọc SCAN_WORKSPACE đã mount vào Docker), Co-work cần đọc/sửa **bất kỳ folder nào trên máy host**, nên chạy qua 1 service riêng:

```bash
# Chạy 1 lần trên máy host (không phải trong Docker), giữ chạy nền:
bash coworker_host/run.sh
```

Sau đó vào Web UI → **Co-work** → "+ Thêm Folder", nhập absolute path trên host. Mọi đọc/ghi/exec đều giới hạn trong các folder đã cấp quyền, có whitelist lệnh + bắt buộc xác nhận cho lệnh lạ, và backup `.vulnguard.bak` trước khi ghi đè. Production systemd template: `install/coworker_host.service.template`.

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
| **Nuclei** | DAST / Web | 10k+ template CVE/misconfig/exposure (quét URL đã crawl) |

> Tất cả tools có thể **bật/tắt riêng lẻ** trong Settings → Scanner Tools.
>
> **Pentest Agent** dùng thêm: **katana** (crawl), **nmap** (port/service), **ffuf** (content discovery), **sqlmap** (SQLi). Cài qua `bash setup.sh` (chọn nhóm Web/Pentest).

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

### ☁️ Cloud AI — giảm false positive (tuỳ chọn)
- Ngoài Ollama local: **Claude API** (API key / **Workload Identity Federation** cho tenant doanh nghiệp / environment) và **Amazon Bedrock** (IAM — nền tảng Kiro dùng).
- 3 chế độ: **local-only** (không gửi gì ra ngoài) · **hybrid** (Ollama chấm trước; finding nặng hoặc FP% không chắc chắn mới gửi Claude xác minh) · **cloud-only**.
- Chính xác hơn nhờ **structured output** + gửi **ngữ cảnh code thật** quanh dòng lỗi; **redact secret** trước khi gửi; API key **mã hoá Fernet**.
- Nút **"Phân tích lại bằng Claude"** cho từng vuln. Cấu hình: **Settings → AI Provider** (chỉ ADMIN).

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

### 📑 Document Review
- Review tài liệu **SRS/FRS/BRD**, **Architecture (HLD/LLD)**, **API/DB Schema** — chấm theo checklist dựa trên **OWASP ASVS/SAMM**
- Upload file `.pdf` / `.docx` / `.md` / `.txt`, AI local (Ollama) đọc và đánh giá từng tiêu chí: **Đã đáp ứng / Một phần / Chưa đáp ứng / Không áp dụng**, kèm evidence trích từ tài liệu + gợi ý bổ sung
- **Versioning**: mỗi lần upload bản mới tạo version tiếp theo, giữ lại toàn bộ lịch sử (không rolling)
- **Gửi lại bên viết tài liệu**: đính kèm ghi chú yêu cầu sửa, track trạng thái `UPLOADED → SENT_FOR_REVISION → ACCEPTED`
- **Compare 2 version**: xem tiêu chí nào cải thiện / regress / vẫn chưa đáp ứng
- Xuất báo cáo HTML để gửi email cho author tài liệu

### 🔑 Đăng nhập & phân quyền (RBAC)
- 3 vai trò: **ADMIN** (cấu hình AI/scanner/connector, quản lý user) · **ANALYST** (chạy scan, đổi trạng thái vuln, waiver) · **VIEWER** (chỉ xem).
- Session **JWT cookie HttpOnly**; tạo ADMIN đầu tiên khi mở app, hoặc `setup.sh` **tự sinh mật khẩu**.
- Tất cả `/api/*` yêu cầu đăng nhập; thao tác ADMIN enforce ở middleware.

### 🌐 Web Scan (Nuclei)
- Quét lỗ hổng web bằng **Nuclei** (10k+ template CVE/misconfig/exposure) trên các URL **katana** đã crawl.
- Stream finding realtime; **bắt buộc xác nhận quyền quét** domain; bảng finding + curl tái hiện.

### 🎯 Pentest Agent — tự động hoá pentest *có kiểm soát*
- Vòng lặp **planner/worker** do Claude lái, chạy công cụ thật (nmap, nuclei, ffuf, sqlmap).
- **Lan can bắt buộc**: scope gate (chặn ngoài phạm vi, loopback) · risk gate (recon/quét an toàn tự chạy; **xâm lấn/phá huỷ cần người duyệt**) · uỷ quyền + hạn · budget bước/token · **kill switch** · audit trail (ai/cái gì quyết định).
- **Chuỗi tấn công bền (todolist)**; **chạy tool song song** (`max_parallel`).
- **Bằng chứng**: gắn request/response thật vào finding; **recording MITM proxy** (CA tự sinh) bắt traffic của tool & trình duyệt; **replay** trong scope.
- Chi tiết: `docs/PENTEST_AGENT.md`.

### 🗂️ Asset Inventory + Risk Scoring theo ngữ cảnh
- Gộp tài sản theo **mac / hostname / ip** (NAC + EDR thấy cùng máy → 1 asset).
- **Điểm rủi ro giải thích được** (kiểu Tenable VPR / Nexpose): `CVSS × EPSS × KEV × độ quan trọng × mức phơi bày`, cộng thêm khi có **cảnh báo EDR đang hoạt động**. Cùng 1 CVE: máy critical/internet có thể 100đ, máy isolated chỉ vài điểm.
- Feed **EPSS** (FIRST) + **CISA KEV**, cache offline; sửa criticality/exposure → tự tính lại.

### 🔌 Connectors XDR/EDR/NAC + MCP
- **Trellix XDR** (OAuth2), **Trend Micro Vision One** (Bearer), **FortiNAC** (token) — kéo asset/alert/software về inventory; secret **mã hoá at-rest**; đường dẫn endpoint cấu hình được.
- Thêm vendor khác = 1 adapter kế thừa `BaseConnector`.
- **MCP server** expose dữ liệu (asset, EPSS/KEV, ngữ cảnh EDR) cho **Pentest Agent / Claude Desktop** (read-only; cô lập host phải qua duyệt).
- Chi tiết: `docs/CONNECTORS_MCP.md`.

### 📊 Dashboard rủi ro toàn hệ thống
- Gom **code + web + pentest + tài sản** thành một **điểm tư thế rủi ro** + nhãn.
- Findings theo nguồn, donut rủi ro tài sản, **top rủi ro**, hàng chờ (chờ duyệt / scan đang chạy), độ phủ, xu hướng scan 14 ngày.

---

## 📁 Cấu trúc Project

```
VulnGuard/
├── setup.sh / run.sh / run_demo.sh   # Cài tương tác · chạy prod · chạy demo
├── docker-compose.yml                # Docker orchestration
├── .env.example / .env.native.example
├── api/
│   ├── Dockerfile  config.py  database.py  main.py
│   ├── models.py  schemas.py                 # Project/Scan/Vulnerability/Waiver
│   ├── security.py  auth_models.py           # JWT, hash, mã hoá secret, User/RBAC
│   ├── asset_models.py  connector_models.py  # Asset inventory, Connector config
│   ├── pentest_models.py  webscan_models.py  docreview_models.py
│   ├── services/            # ollama_client, ai_config, chat/file/summarizer...
│   └── routes/
│       ├── auth.py          # Đăng nhập, RBAC, quản lý user
│       ├── ai.py            # Cloud AI (Claude/Bedrock) config + reanalyze
│       ├── projects.py scans.py vulns.py compare.py report.py settings.py ollama.py
│       ├── webscans.py      # Web scan (Nuclei)
│       ├── domains.py       # Domain sitemap / crawl (katana)
│       ├── pentest.py       # Pentest Agent: engagement/run/approval/traffic/proxy
│       ├── assets.py intel.py connectors.py   # Asset inventory, EPSS/KEV, XDR/EDR/NAC
│       ├── dashboard.py     # Dashboard rủi ro tổng hợp
│       └── docreview.py coworker.py file_assistant.py
├── scanner/
│   ├── orchestrator.py  ai_analyzer.py  cloud_ai.py   # scan engine + AI (local/cloud)
│   ├── scanners/        # sast, sca, container, iac, secrets (+ rules offline)
│   ├── crawler/         # katana_runner, nuclei_runner, waf_export
│   ├── intel/feeds.py   # EPSS (FIRST) + KEV (CISA), cache offline
│   ├── assets/          # scoring.py (risk), service.py (dedup/upsert/recompute)
│   ├── connectors/      # base + trellix / trendmicro / fortinac + registry + sync + MITM proxy
│   └── pentest/         # agent, toolbelt, gating, scope, traffic, proxy (Pentest Agent)
├── mcp_server/server.py              # MCP server (expose asset/intel cho agent/Claude Desktop)
├── scripts/                          # seed_demo.py, bootstrap_admin.py
├── web/                              # index.html (SPA), login.html, agent.html, brand.css
├── docs/                             # PENTEST_AGENT.md, CONNECTORS_MCP.md, BRAND.md, screenshots
└── storage/                          # SQLite, config, secret.key, pentest_ca, intel cache
```

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

# Document Review
GET    /api/docreview/doc-types                Danh sách loại tài liệu + checklist
GET    /api/docreview/documents                Danh sách tài liệu
POST   /api/docreview/documents                Tạo tài liệu mới (upload version 1)
GET    /api/docreview/documents/{id}           Chi tiết tài liệu (kèm version mới nhất)
DELETE /api/docreview/documents/{id}           Xóa tài liệu + toàn bộ version/file
GET    /api/docreview/documents/{id}/versions  Lịch sử version
GET    /api/docreview/documents/{id}/compare   So sánh 2 version (improved/regressed)
POST   /api/docreview/documents/{id}/versions  Upload version mới
GET    /api/docreview/versions/{id}            Chi tiết version + findings
POST   /api/docreview/versions/{id}/review     (Re)trigger AI review
GET    /api/docreview/versions/{id}/progress   Poll trạng thái review
PATCH  /api/docreview/versions/{id}/send-back  Gửi lại bên viết tài liệu (kèm note)
PATCH  /api/docreview/versions/{id}/accept     Chấp nhận tài liệu
GET    /api/docreview/versions/{id}/export     Xuất báo cáo HTML

# ── Auth & RBAC ──
GET    /api/auth/status                        setup_required / auth_enabled
POST   /api/auth/setup | /api/auth/login | /api/auth/logout | GET /api/auth/me
GET/POST/PATCH/DELETE /api/auth/users          Quản lý user (ADMIN)

# ── Cloud AI (Claude / Bedrock) ──
GET/PUT /api/ai/config                         Cấu hình provider (ADMIN)
POST   /api/ai/test                            Kiểm tra kết nối cloud
POST   /api/vulns/{id}/reanalyze               Phân tích lại 1 vuln bằng Claude

# ── Web Scan (Nuclei) ──
POST/GET /api/domains/{id}/webscans | GET /api/webscans/{id}[/findings]
PATCH  /api/webscans/findings/{id}/status

# ── Pentest Agent ──
CRUD   /api/pentest/engagements                Scope + uỷ quyền
POST/GET /api/pentest/engagements/{id}/runs    Khởi chạy / liệt kê run
GET    /api/pentest/runs/{id}[/steps|/findings|/approvals|/traffic]
POST   /api/pentest/approvals/{id}/decision    Duyệt/từ chối hành động
POST   /api/pentest/runs/{id}/stop             Kill switch
POST   /api/pentest/findings/{id}/evidence | /api/pentest/traffic/{id}/replay
*      /api/pentest/engagements/{id}/proxy/{start,stop} | GET /api/pentest/proxy/ca.crt

# ── Asset inventory + Risk + Threat intel ──
GET    /api/assets[?sort=risk] | /api/assets/summary | /api/assets/{id}
PATCH  /api/assets/{id}  (criticality/exposure) | POST /api/assets/recompute
GET    /api/intel/status | POST /api/intel/refresh   (EPSS/KEV)

# ── Connectors (XDR/EDR/NAC) ── (ADMIN)
GET    /api/connectors/kinds | CRUD /api/connectors
POST   /api/connectors/{id}/test | /api/connectors/{id}/sync

# ── Dashboard ──
GET    /api/dashboard/overview                 Tổng hợp rủi ro toàn hệ thống

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

# ── Auth (đăng nhập Web UI) ──
AUTH_ENABLED=true            # false chỉ cho dev 1 người
VULNGUARD_SECRET_KEY=        # trống = tự sinh storage/secret.key (ký session + mã hoá secret)
SESSION_TTL_HOURS=12
COOKIE_SECURE=false          # true khi chạy sau HTTPS

# ── Web Scan (Nuclei) ──
MAX_WEBSCANS_PER_DOMAIN=5
NUCLEI_TIMEOUT_MINUTES=60

# ── Pentest proxy (bắt bằng chứng) ──
PENTEST_PROXY_PORT=8788

# Native (run.sh/setup.sh tự đặt): DEPLOY_MODE=native, DATABASE_URL, AI_CONFIG_FILE
```

> **Cloud AI** (Claude API key / WIF / Bedrock) cấu hình trong **Settings → AI Provider** (mã hoá at-rest), không qua `.env`.

---

## 🔒 Bảo mật & Privacy

- **Mặc định hoàn toàn local**: Ollama + scanner chạy tại chỗ, không gửi code/kết quả ra ngoài.
- **Đăng nhập + RBAC** (ADMIN/ANALYST/VIEWER); `setup.sh` tự sinh mật khẩu ADMIN. Session JWT cookie HttpOnly.
- **Secret mã hoá at-rest** (Fernet): API key cloud AI, credential connector XDR/NAC — chỉ hiện hint, không lộ raw.
- **Cloud AI là tuỳ chọn** (opt-in). Khi bật hybrid/cloud, chỉ gửi finding + ngữ cảnh code đã **redact secret** lên Claude/Bedrock; chế độ local-only không gửi gì ra ngoài.
- **Pentest Agent** chỉ chạy trong **scope đã uỷ quyền**; hành động phá huỷ qua người duyệt; có audit trail đầy đủ.
- Database SQLite + `storage/secret.key` (chmod 600) + `storage/admin_credentials.txt` — nhớ backup & bảo vệ.
- Docker socket mount chỉ dùng để scan container images.

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
