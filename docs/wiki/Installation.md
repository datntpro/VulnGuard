# Cài đặt

VulnGuard có 4 cách chạy. Tất cả đều dùng chung mã trong `api/`, `scanner/`, `web/`.

| Cách | Lệnh | Thư mục venv | Bind mặc định |
|---|---|---|---|
| Installer đa nền tảng (Native) | `bash setup.sh` / `python3 scripts/setup.py` | `.venv/` | xem lưu ý bên dưới |
| Chạy lại bản Native | `bash run.sh` (Windows: `.\run.ps1`) | `.venv/` | `127.0.0.1` |
| Docker Compose | `bash setup.sh --docker` hoặc `docker compose up -d --build` | trong image | cổng publish trên mọi interface của host |
| systemd (Oracle Linux / RHEL / Debian / Ubuntu) | `sudo bash install/install.sh` | `venv/` | `0.0.0.0` (theo `install/vulnguard.service.template`) |
| Demo có dữ liệu mẫu | `bash run_demo.sh` | `.venv-demo/` | `0.0.0.0` |

## Yêu cầu

- Python **3.11+** cho Native (`setup.sh` và `setup.ps1` kiểm tra có `python3`/`python`). Docker image dùng `python:3.11-slim`.
- Hoặc Docker + Docker Compose.
- Công cụ quét chỉ cần khi quét thật. Chỉ dùng UI / Document Review thì có thể bỏ qua.
- Windows: `semgrep` không chạy native, installer khuyên dùng Docker/WSL cho SAST Semgrep.
- macOS: nên có Homebrew để installer cài CLI tool.
- Ollama (tuỳ chọn) cho AI local, mặc định model `llama3.2`.

## 1. Native bằng installer đa nền tảng (khuyên dùng)

```bash
git clone https://github.com/datntpro/VulnGuard.git
cd VulnGuard
bash setup.sh --mode native --tools sast,sca,secrets,iac,web --no-run
bash run.sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File setup.ps1 --mode native --tools sast,sca,secrets --no-run
.\run.ps1
```

### Cờ của `scripts/setup.py`

| Cờ | Ý nghĩa |
|---|---|
| `--mode docker\|native` | Chọn cách chạy. Chế độ tương tác mặc định là Docker nếu bấm Enter |
| `--docker` | Như `--mode docker` |
| `--tools <nhóm>` | Danh sách nhóm, cách nhau bởi dấu phẩy hoặc dấu cách. `all` = `sast sca secrets iac container web pentest` (không gồm `ai`, `sonar`). `none` = không cài tool |
| `--no-run` | Cài xong không chạy server |
| `--check` | Chỉ in trạng thái các tool |
| `--admin-email <email>` | Email ADMIN đầu tiên (mặc định `admin@vulnguard.local`) |
| `--skip-admin` | Không tạo ADMIN |

### Nhóm công cụ

| Nhóm | Cài gì | Cách cài |
|---|---|---|
| `sast` | semgrep (trừ Windows), bandit | `pip` vào `.venv` |
| `sca` | pip-audit, trivy | `pip` vào `.venv`; trivy qua trình quản lý gói hoặc script chính thức |
| `secrets` | detect-secrets, gitleaks | `pip`; gitleaks qua trình quản lý gói |
| `iac` | checkov, hadolint | `pip`; hadolint qua trình quản lý gói |
| `container` | grype | trình quản lý gói hoặc script chính thức |
| `web` | katana 1.5.0, nuclei 3.4.7 | tải binary release, rồi `nuclei -update-templates` |
| `pentest` | nmap, sqlmap, ffuf 2.1.0 | trình quản lý gói / binary; trên Linux clone SecLists vào `/usr/share/seclists` (dùng `sudo`) |
| `ai` | Ollama | script `ollama.com/install.sh` trên Linux; macOS/Windows tự tải |
| `sonar` | sonar-scanner CLI 6.2.1.4610 | brew (macOS) hoặc zip chính thức |

Binary được đặt vào `/usr/local/bin` nếu ghi được, nếu không thì `~/.local/bin` (Windows: `%LOCALAPPDATA%\VulnGuard\bin`). Hãy chắc thư mục này có trong `PATH`.

### Tài khoản ADMIN đầu tiên

`scripts/bootstrap_admin.py` chạy sau khi cài:

- Nếu DB đã có user thì bỏ qua.
- Mật khẩu lấy từ biến `ADMIN_PASSWORD`, nếu không có thì sinh ngẫu nhiên 20 ký tự.
- Mật khẩu **không** in ra màn hình. Nó được ghi vào `storage/admin_credentials.txt` (chmod 600, đã nằm trong `.gitignore`).
- User được đánh dấu `must_change_password=True`. UI bắt đổi mật khẩu ở lần đăng nhập đầu.

Việc cần làm: mở file, đăng nhập, đổi mật khẩu, rồi **xoá file**.

Nếu không chạy bootstrap, lần đầu mở app sẽ hiện màn hình tạo ADMIN (`POST /api/auth/setup`, chỉ dùng được khi DB chưa có user nào).

> **Nên dùng `--no-run` rồi `bash run.sh`.** Khi `setup.py` tự chạy server (không có `--no-run`), nó gọi `uvicorn --host 0.0.0.0` và không thêm `.venv/bin` vào `PATH`. Khi đó app nghe trên mọi interface và các tool cài trong `.venv` (semgrep, bandit, pip-audit, detect-secrets, checkov) sẽ bị báo `skipped`. `run.sh` thì nghe `127.0.0.1` và đưa `.venv/bin` lên đầu `PATH`.

### `run.sh` làm gì

- Nạp `.env` nếu có.
- Đặt mặc định: `DATABASE_URL=sqlite:///$PWD/storage/db/vulnguard.db`, `AI_CONFIG_FILE`, `SCANNER_CONFIG_FILE` trong `storage/`, `AUTH_ENABLED=true`, `APP_ENV=production`, `DEPLOY_MODE=native`.
- `PATH="$PWD/.venv/bin:$HOME/.local/bin:$PATH"`.
- Host: `VULNGUARD_HOST` (mặc định `127.0.0.1`), cổng `VULNGUARD_PORT` (mặc định `8080`), số worker `VULNGUARD_WORKERS` (mặc định `1`).

## 2. Docker Compose

```bash
cp .env.example .env        # sửa SCAN_WORKSPACE trỏ tới thư mục mã nguồn cần quét
docker compose up -d --build
# SonarQube tuỳ chọn:
docker compose --profile sonar up -d
```

Theo `docker-compose.yml`:

- Service `vulnguard` (container `vulnguard-api`) build từ `api/Dockerfile`, image có sẵn trivy, gitleaks, hadolint, grype, katana, nuclei 3.4.7, ffuf 2.1.0, sonar-scanner và các tool Python.
- Cổng publish: `${VULNGUARD_PORT:-8080}:8080` và `${PENTEST_PROXY_PORT:-8788}:8788` (MITM proxy).
- Volume: `./storage:/app/storage`, `${SCAN_WORKSPACE:-/tmp}:/workspace`. **Không còn mount `docker.sock`** (mount `:ro` vẫn cho phép tạo container privileged → root trên host).
- Container chạy non-root (uid 10001). Nếu `./storage` thuộc root (nâng cấp từ bản cũ): `sudo chown -R 10001:10001 storage` (không dùng `chmod 777`); entrypoint sẽ báo lỗi kèm lệnh này nếu thư mục không ghi được.
- `OLLAMA_URL=http://host.docker.internal:11434` (Ollama chạy trên host), `COWORKER_URL=http://host.docker.internal:8765`.
- Profile `sonar`: `sonarqube:community` + `postgres:16-alpine`. Host Linux cần `sysctl -w vm.max_map_count=524288`.

### Quét image chỉ có ở máy local (tuỳ chọn)

Image công khai quét được ngay (Trivy tự pull từ registry). Để quét image **chỉ có ở Docker daemon local**, dùng override `docker-compose.local-images.yml`: app nói chuyện với `tecnativa/docker-socket-proxy` (pin digest) chỉ cho phép `GET /_ping`, `/version`, `/images/*`; mọi `POST` (tạo container, exec, build) bị `403`. Cổng proxy không publish ra host.

```bash
docker compose -f docker-compose.yml -f docker-compose.local-images.yml up -d
# macOS Docker Desktop: đặt DOCKER_SOCK=$HOME/.docker/run/docker.sock trong .env nếu /var/run/docker.sock không tồn tại
```

### Supply chain: lockfile và binary được pin

- Python: `api/requirements.in` là nguồn; `api/requirements.txt` là lockfile **có hash**, sinh bằng
  `uv pip compile --universal --python-version 3.11 --generate-hashes api/requirements.in -o api/requirements.txt`. Dockerfile cài một lần với `--require-hashes`.
- Scanner CLI (semgrep, bandit, checkov, pip-audit) mỗi cái một venv riêng từ `docker/scanners/<tool>.txt` (không chia sẻ dependency với app). `detect-secrets` ở lại env của app vì được import như thư viện.
- Binary (trivy, gitleaks, grype, hadolint, katana, nuclei, ffuf, sonar-scanner) tải theo phiên bản cố định và kiểm `sha256` theo kiến trúc (`ARG *_SHA256_AMD64/_ARM64` trong `api/Dockerfile`; lấy từ file checksums chính thức của release). Tool lõi lỗi → build fail; tool tuỳ chọn lỗi → bỏ qua kèm cảnh báo. SecLists pin theo tag.
- `.github/dependabot.yml` mở PR hàng tuần cho pip/docker/actions; sau khi merge PR đổi `.txt`, chạy lại lệnh compile để đồng bộ với `.in`.
- `FORWARDED_ALLOW_IPS` (mặc định `127.0.0.1`): chỉ tin `X-Forwarded-For` từ các IP này. Đặt IP reverse proxy nếu có.

Khi tạo scan trong Docker, `scan_path` là đường dẫn **trong container** (ví dụ `/workspace/my-app`).

## 3. systemd (`install/install.sh`)

Dành cho máy không cài được Docker (nhắm tới Oracle Linux 8/9, vẫn hỗ trợ apt):

```bash
sudo bash install/install.sh
sudo systemctl status vulnguard
```

Script cài system package, các binary scanner, tạo `venv/`, pre-cache Semgrep rules, tạo `.env` từ `.env.native.example`, và đăng ký service. Chạy tay không qua systemd: `bash install/run.sh` (cần `venv/` và `.env`). Gỡ: `sudo bash install/uninstall.sh` (thêm `--purge` để xoá cả venv và storage). Chi tiết: `docs/NATIVE_INSTALL.md` trong repo.

## 4. Demo

```bash
bash run_demo.sh            # tạo .venv-demo, seed dữ liệu, chạy server
bash run_demo.sh --no-seed  # chạy lại, giữ dữ liệu
```

Đăng nhập demo: `demo@vulnguard.local` / `VulnGuardDemo!` (công khai trong README, chỉ dùng cho dữ liệu demo). DB demo ở `storage/demo/`. Script này bind `0.0.0.0`.

## Kiểm tra sau khi cài

```bash
curl -s http://127.0.0.1:8080/api/health
# {"status":"ok","service":"VulnGuard","deploy_mode":"native"}
bash setup.sh --check
```

Swagger: `http://127.0.0.1:8080/docs` (cần đăng nhập cho các API `/api/*`).

## Cập nhật code mới

- Docker: `docker compose up -d --build`. Thiếu `--build` thì container vẫn chạy image cũ.
- Native: dừng tiến trình cũ trên cổng 8080 trước khi `bash run.sh` (xem [[Troubleshooting]]).
- Chỉ chạy **một** kiểu (Native hoặc Docker) trên cùng cổng.

## Gỡ cài (Native)

Dữ liệu nằm trong `storage/` của thư mục repo. Ngoài thư mục repo, installer còn có thể ghi:

- binary scanner vào `/usr/local/bin` hoặc `~/.local/bin` (Windows: `%LOCALAPPDATA%\VulnGuard\bin`), sonar-scanner vào thư mục `sonar-scanner/` cạnh thư mục bin đó;
- SecLists vào `/usr/share/seclists` (nhóm `pentest` trên Linux);
- Ollama (nhóm `ai`);
- dữ liệu Coworker Host vào `~/.vulnguard_coworker` (nếu chạy `coworker_host/run.sh`).

Xoá thư mục repo (gồm `.venv/` và `storage/`) và các mục trên nếu không cần nữa.
