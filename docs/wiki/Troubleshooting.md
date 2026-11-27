# Troubleshooting

## Đã pull code mới nhưng giao diện vẫn cũ

Thường do **instance cũ vẫn chạy trên cổng 8080** hoặc **Docker image chưa build lại**. Nhận biết UI mới: sidebar có mục **Tuân thủ** và **Nguồn mã (SCM)**.

Docker:

```bash
docker compose down
docker ps                    # không còn container vulnguard
docker compose up -d --build # bắt buộc --build
```

Native:

```bash
docker compose down          # nếu trước đó chạy Docker
lsof -i :8080                # tìm PID đang giữ cổng 8080 rồi dừng nó
bash run.sh                  # banner in "VulnGuard PRODUCTION:  http://127.0.0.1:8080"
```

Nếu báo `address already in use` thì cổng vẫn bị chiếm. Cuối cùng hard refresh trình duyệt (`Cmd/Ctrl + Shift + R`).

## DB không ghi được sau khi nâng cấp lên image non-root

Triệu chứng: container thoát ngay với `❌ /app/storage/db không ghi được...` (hoặc `attempt to write a readonly database`). Nguyên nhân: `./storage` do bản cũ (chạy root) tạo, thuộc `root`. Sửa trên máy host (không dùng `chmod 777`):

```bash
sudo chown -R 10001:10001 storage
docker compose up -d
```

## Quét image local báo không thấy image

Mặc định app không mount `docker.sock`. Image công khai vẫn quét được; image chỉ có ở máy local cần override socket-proxy chỉ-đọc: `docker compose -f docker-compose.yml -f docker-compose.local-images.yml up -d`.

## Docker đã down nhưng vẫn đăng nhập được

Còn server khác trên 8080 (container khác hoặc tiến trình native). Dùng `docker ps` và `lsof -i :8080`.

## Scan báo "0 lỗi" hoặc tool bị bỏ qua

Mở chi tiết scan hoặc báo cáo HTML, mục **Công cụ đã dùng**. Tool **BỎ QUA (chưa cài / thiếu PATH)** nghĩa là kết quả không đầy đủ.

- Chạy app bằng `bash run.sh` (tự thêm `.venv/bin` và `~/.local/bin` vào `PATH`). Chạy server trực tiếp từ `setup.sh` (không `--no-run`) hoặc uvicorn tự gọi thì không có các đường dẫn này.
- Cài tool còn thiếu: `bash setup.sh --no-run` (xem [[Installation]]).
- **Trivy IaC luôn bị bỏ qua** dù đã cài `trivy`: lỗi đã biết (orchestrator tìm binary `trivy-iac`). IaC vẫn được Checkov quét.

## Xác minh domain bằng DNS TXT luôn thất bại

- Kiểm tra bản ghi: `dig TXT example.com +short` phải thấy `"vulnguard-verify=<token>"` trên đúng host của domain.
- Code cần gói `dnspython` nhưng `api/requirements.txt` không khai báo. Cài trong venv của app: `.venv/bin/pip install dnspython` rồi khởi động lại, hoặc dùng cách file `https://<host>/.well-known/vulnguard.txt`.

## Quét web / crawl / pentest bị chặn (403)

- `AUTH_ENABLED=false`: các tính năng quét chủ động bị khoá. Bật auth và đăng nhập.
- Domain chưa xác minh sở hữu (crawl, web scan).
- `fuzz=true` cần ADMIN.
- Pentest: engagement chưa được ADMIN uỷ quyền, đã hết hạn, hoặc target ngoài scope.

## Nuclei không ra kết quả mới

Web scan chạy Nuclei với `-duc` (không tự cập nhật). Cập nhật template: `nuclei -update-templates`.

## CLI báo 401

`python -m scanner.cli scan --project <tên> --path <thư mục> --api http://127.0.0.1:8080` không gửi token, nên bị từ chối khi `AUTH_ENABLED=true`. Dùng giao diện web, hoặc gọi REST API trực tiếp với `Authorization: Bearer <token>` (xem [[Authentication and Roles|Authentication-and-Roles]]).

## Không truy cập được từ máy khác

`run.sh` và Docker mặc định chỉ nghe `127.0.0.1`. Mở LAN: `VULNGUARD_BIND=0.0.0.0` — xem [[Truy cập từ máy khác trong LAN|LAN-Access]] (cần auth + `ALLOWED_HOSTS` + firewall). Nếu thấy app nghe `0.0.0.0` ngoài ý muốn: kiểm tra `VULNGUARD_BIND`/`VULNGUARD_HOST` trong `.env`/môi trường.

## AI đám mây lỗi

- Chưa nhập API key đúng provider (Settings › AI), hoặc dùng nút **Test** (`POST /api/ai/test`). Khoá riêng của bạn: Settings › AI › Khoá AI của tôi. Mã lỗi: [[Per-user AI keys|AI-Per-User-Keys]].
- Pentest Agent chỉ chạy với Anthropic hoặc Bedrock. OpenAI/OpenRouter/Ollama không dùng được cho agent.

## Ollama không kết nối

Chạy `ollama serve` trên host hoặc trỏ địa chỉ khác ở Settings › AI › Ollama. Trong Docker, `OLLAMA_URL` là `http://host.docker.internal:11434`.

## MCP HTTP bị từ chối

Chế độ `--http` bắt buộc `VULNGUARD_MCP_TOKEN` và header `Authorization: Bearer <token>`. Xem [[MCP Server|MCP-Server]].

## Lỡ commit nhầm secret

`.gitignore` hiện **không** bao gồm `storage/secret.key`, `storage/ai_config.json`, `storage/runtime_settings.json`. Đừng `git add` thư mục `storage/`. Nếu lỡ commit: xoay khoá / đổi mật khẩu / thu hồi token liên quan, xoá khỏi lịch sử git, và không dùng lại secret đó. Lưu ý đổi `secret.key` làm mất khả năng giải mã các secret đã lưu (phải nhập lại) và vô hiệu mọi phiên đăng nhập.

## PDF không xuất được

Chạy `python -m scanner.pdf.selftest` (hoặc `python3 scripts/setup.py --check`): lệnh in từng bước đạt/lỗi và cách sửa. Nguyên nhân thường gặp: wheel `typst` chưa cài (cài lại lockfile: `pip install --require-hashes -r api/requirements.txt`), Windows ARM64 (không có wheel; dùng Python x64 hoặc Docker), hoặc thiếu thư mục font `scanner/assets/fonts` (kiểm tra bản `git pull` đầy đủ). Không cần Chromium/trình duyệt.

Ghi chú: bước `@preview import blocked` của self-test chỉ đạt khi việc tải package bị **từ chối kết nối** (proxy chết, không có mạng). Nếu tải được hoặc lỗi vì lý do khác, self-test báo FAIL (mạng chưa bị chặn thật). `run.ps1` chạy self-test với `$ErrorActionPreference="Continue"` cục bộ để Windows PowerShell 5.1 không coi stderr là lỗi dừng script.
