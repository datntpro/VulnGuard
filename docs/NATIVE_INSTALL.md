# 🛡️ VulnGuard — Cài đặt Native (không cần Docker)

Bản này dành cho các máy **không thể cài Docker** (chính sách công ty, máy nội bộ
hạn chế quyền, môi trường air-gapped...). VulnGuard chạy trực tiếp trên host bằng
Python virtualenv + systemd, không qua container.

> Nếu máy bạn cài được Docker, nên dùng bản Docker mặc định (xem README.md) —
> đơn giản hơn và cách ly tốt hơn. Bản native chỉ nên dùng khi không còn lựa chọn.

---

## Khác biệt so với bản Docker

| | Bản Docker | Bản Native |
|---|---|---|
| Cài đặt | `docker compose up` | `install/install.sh` (apt + pip + binary) |
| Cách ly | Container riêng | Chạy trực tiếp trên host |
| Service | Docker daemon quản lý | systemd quản lý |
| Scan path | Path trong container (`/workspace/...`) | Path thật trên máy (`/home/user/...`) |
| Scan CONTAINER (image) | Hoạt động đầy đủ (mount docker.sock) | **Hạn chế** — cần Docker daemon, khuyên tắt nếu máy không có Docker |
| Update | `docker compose build --no-cache` | `git pull` + chạy lại `install.sh` |

---

## Yêu cầu hệ thống

| | Tối thiểu | Khuyến nghị |
|---|---|---|
| **OS** | Ubuntu 20.04+ / Debian 11+ | Ubuntu 22.04 |
| **RAM** | 8 GB | 16 GB (cho AI model) |
| **Disk** | 10 GB | 20 GB |
| **Quyền** | sudo/root (để cài system packages + systemd) | |
| **Ollama** | Cài trên máy host | |

---

## Bước 1 — Cài Ollama (AI Analysis)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2          # Recommended (4GB, cân bằng tốt)
# ollama pull deepseek-coder:6.7b   # Tốt hơn cho code analysis (8GB RAM)
# ollama pull phi3:mini             # Máy yếu <8GB RAM
```

Kiểm tra: `curl http://localhost:11434/api/tags`

---

## Bước 2 — Chạy script cài đặt

```bash
cd VulnGuard
sudo bash install/install.sh
```

Script này tự động:
1. Cài system packages (`python3-venv`, `git`, `curl`...) qua `apt`
2. Cài scanner binaries: **Trivy** (apt repo), **Gitleaks**, **Hadolint**, **Grype**
   (download release tương ứng kiến trúc máy — amd64/arm64)
3. Tạo Python virtualenv tại `VulnGuard/venv/`
4. Cài API deps + scanner Python packages: **Semgrep, Bandit, Checkov,
   detect-secrets, pip-audit**
5. Tạo `.env` từ `.env.native.example` (nếu chưa có)
6. Tạo thư mục `storage/db`, `storage/reports`
7. Đăng ký + khởi động **systemd service** `vulnguard.service`

Thời gian cài lần đầu: ~10-20 phút (tùy tốc độ mạng tải Semgrep/Trivy rules).

---

## Bước 3 — Cấu hình `.env`

Mở `.env` (đã được tạo ở bước 2), sửa:

```bash
SCAN_WORKSPACE=/home/user/projects   # Thư mục thật chứa source code cần scan
OLLAMA_MODEL=llama3.2                # Phải khớp model đã `ollama pull`
```

Khác với bản Docker, **không cần path container** — nhập trực tiếp path thật
trên máy khi Trigger Scan trong Web UI (ví dụ `/home/user/projects/my-app`).

Sau khi sửa `.env`:

```bash
sudo systemctl restart vulnguard
```

---

## Bước 4 — Mở Web UI

```
http://localhost:8080
```

---

## Quản lý service

```bash
sudo systemctl status vulnguard      # Trạng thái
sudo systemctl restart vulnguard     # Restart sau khi sửa .env
sudo systemctl stop vulnguard
journalctl -u vulnguard -f           # Xem logs realtime
```

Service tự khởi động lại khi máy reboot (đã `systemctl enable`).

Nếu máy không có systemd (hiếm), dùng script chạy thủ công:

```bash
bash install/run.sh
```

---

## Update lên version mới

```bash
cd VulnGuard
git pull
sudo bash install/install.sh   # Chạy lại — tự skip phần đã cài, update pip packages
```

---

## Gỡ cài đặt

```bash
sudo bash install/uninstall.sh            # Gỡ service, giữ database + reports
sudo bash install/uninstall.sh --purge    # Gỡ sạch — XÓA luôn venv + storage (mất data)
```

Scanner binaries (`trivy`, `gitleaks`, `hadolint`, `grype` tại `/usr/local/bin`)
không bị gỡ tự động vì có thể dùng cho việc khác — gỡ tay nếu cần.

---

## ⚠️ Hạn chế của bản Native

**Scan loại CONTAINER (quét image Docker)** cần Docker daemon để pull/inspect
image — máy không cài Docker thì phần này sẽ lỗi hoặc trả về rỗng. Các loại
scan khác (**SAST, SCA, IaC, Secrets**) hoạt động đầy đủ bình thường.

Khuyến nghị: vào **Settings → Scanner Tools** trong Web UI, tắt
`trivy-container` nếu máy không có Docker (Grype vẫn quét được filesystem
dependencies, chỉ phần quét image là bị ảnh hưởng).

---

## 🐛 Troubleshooting

**Service không start:**
```bash
journalctl -u vulnguard -n 50 --no-pager
```

**Lỗi "command not found" cho scanner tool:**
```bash
# Kiểm tra tool đã cài đúng path chưa
which trivy gitleaks hadolint grype
source venv/bin/activate && which semgrep bandit checkov detect-secrets pip-audit
```

**AI Analysis không chạy:**
```bash
ollama list
curl http://localhost:11434/api/tags
# Nếu chưa chạy: ollama serve
```

**Đổi port:** sửa `VULNGUARD_PORT` trong `.env`, sau đó `sudo bash install/install.sh`
lại (script tự ghi đè service file với port mới) hoặc sửa trực tiếp
`/etc/systemd/system/vulnguard.service` rồi `systemctl daemon-reload && systemctl restart vulnguard`.

**Rebuild venv từ đầu:**
```bash
sudo systemctl stop vulnguard
rm -rf venv
sudo bash install/install.sh
```
