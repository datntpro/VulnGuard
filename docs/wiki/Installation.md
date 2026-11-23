# Installation

VulnGuard chạy được theo 2 kiểu: **native** (setup.sh/run.sh) hoặc **Docker**. Chọn **một** kiểu để tránh xung đột cổng.

## Yêu cầu
- Python 3.11+ (native), hoặc Docker + Docker Compose.
- Git. Một số scanner (semgrep, bandit, pip-audit, detect-secrets) cài qua pip trong `.venv`; trivy/gitleaks/nuclei cài binary.
- RAM ≥ 4GB (≥ 8GB nếu bật SonarQube bundled).

## A. Native (Linux / macOS)
```bash
git clone https://github.com/datntpro/VulnGuard.git && cd VulnGuard
bash setup.sh      # tạo .venv, cài scanner; cho chọn nhóm tool
bash run.sh        # chạy http://127.0.0.1:8080
```
- `setup.sh` sinh mật khẩu ADMIN vào `storage/admin_credentials.txt` (chmod 600, **không in ra màn hình**) và bắt đổi mật khẩu lần đăng nhập đầu.
- Mặc định app **chỉ nghe `127.0.0.1`**. Mở ra LAN:
```bash
VULNGUARD_HOST=0.0.0.0 bash run.sh
```

## B. Windows
```powershell
git clone https://github.com/datntpro/VulnGuard.git; cd VulnGuard
.\setup.ps1
.\run.ps1
```

## C. Docker
```bash
docker compose up -d --build     # LUÔN --build khi code mới để không dùng image cũ
```
- Bật SonarQube bundled (nặng RAM): `docker compose --profile sonar up -d`.
- Ollama chạy trên máy thật (không trong Docker); container gọi qua `host.docker.internal:11434`.

> ⚠️ **Đổi code mà UI không đổi?** Với Docker phải `--build` (image cũ = code cũ). Với native phải chắc chắn cổng 8080 không còn instance cũ. Xem [Troubleshooting](Troubleshooting).

## Scanner cài ở đâu
`setup.sh` ưu tiên `/usr/local/bin`; nếu không ghi được thì `~/.local/bin` (đã thêm vào PATH của `run.sh`). Nếu một tool thiếu, scan sẽ **báo "bỏ qua"** chứ không im lặng trả "0 lỗi".

## Gỡ cài
Xóa thư mục repo + `.venv`. Dữ liệu nằm trong `storage/` (SQLite + config). Không ghi ra ngoài thư mục repo ở chế độ native.
