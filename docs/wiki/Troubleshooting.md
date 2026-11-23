# Troubleshooting

## "Đã pull code mới nhưng giao diện vẫn cũ"
Gần như luôn do **vẫn còn instance cũ chạy trên cổng 8080** hoặc **Docker image chưa build lại**.

**Nhận biết UI mới**: sidebar có **🛡️ Tuân thủ** và **🔗 Nguồn mã (SCM)**. Nếu thiếu → đang xem bản cũ.

**Docker** (image cũ = code cũ):
```bash
docker compose down
docker ps                    # phải KHÔNG còn container vulnguard
docker compose up -d --build # BẮT BUỘC --build
```

**Native** (giải phóng cổng rồi chạy lại):
```bash
docker compose down          # nếu trước đó chạy Docker
lsof -i :8080                # kill PID nào đang giữ 8080
bash run.sh                  # phải thấy "Uvicorn running on http://127.0.0.1:8080"
```
Nếu `run.sh` báo **"address already in use"** → cổng vẫn bị instance cũ chiếm.

Cuối cùng **hard refresh** trình duyệt: `Cmd/Ctrl + Shift + R`.

## "docker đã down nhưng vẫn login được"
Có server khác vẫn chạy trên 8080 (container khác, hoặc tiến trình native cũ). Dùng `docker ps` + `lsof -i :8080` để tìm và tắt.

## Scan báo "0 lỗi" / tool bị bỏ qua
Mở chi tiết scan → mục **"Công cụ đã dùng"**. Tool trạng thái **⊘ BỎ QUA** nghĩa là chưa cài / không có trong PATH → kết quả KHÔNG đầy đủ. Cài tool đó (`bash setup.sh`) hoặc đảm bảo `.venv/bin` + `~/.local/bin` trong PATH.

## Không truy cập được từ máy khác
Mặc định app nghe `127.0.0.1`. Mở LAN: `VULNGUARD_HOST=0.0.0.0 bash run.sh` (đảm bảo có auth + firewall).

## Quét web/crawl/pentest bị chặn
- `AUTH_ENABLED=false` → các tính năng quét chủ động bị khoá. Bật auth và đăng nhập.
- Domain **chưa xác minh sở hữu** → xác minh (DNS TXT / `/.well-known/vulnguard.txt`) trước.

## AI đám mây lỗi
- Chưa nhập API key đúng provider (Settings → AI Provider).
- Pentest Agent cần Claude (Anthropic/Bedrock) cho vòng lặp tool-use; OpenAI/OpenRouter chưa hỗ trợ cho Pentest Agent.

## Ollama không kết nối
Cài native `ollama serve` (không cần Docker) hoặc trỏ IP ở Settings → Ollama. Trong Docker dùng `http://host.docker.internal:11434`.

## MCP HTTP bị từ chối
Chế độ `--http` **bắt buộc** `VULNGUARD_MCP_TOKEN` và gửi header `Authorization: Bearer <token>`.

## Lỡ commit nhầm secret
`storage/secret.key`, `admin_credentials.txt`, `ai_config.json`, `runtime_settings.json` phải nằm trong `.gitignore`. Nếu lỡ commit: xoay khóa, xoá khỏi lịch sử, và không dùng lại secret đó.
