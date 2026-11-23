# Luồng dữ liệu — dữ liệu nào ở lại máy, dữ liệu nào rời máy

> Mục tiêu: nói **đúng** về quyền riêng tư. VulnGuard là local-first, nhưng một số tính
> năng là **opt-in** và CÓ gửi dữ liệu ra ngoài. Trang này liệt kê rõ ràng.

## Luôn ở lại máy (local-only)
| Dữ liệu | Ở đâu |
|---|---|
| Mã nguồn được quét | Chỉ đọc tại chỗ; không upload |
| Kết quả scan, lỗ hổng, triage, báo cáo | SQLite `storage/db/` |
| Secret đã cấu hình (API key cloud, token connector) | Mã hoá Fernet trong `storage/` |
| Phân tích AI bằng **Ollama** | Chạy trên máy/endpoint bạn khai báo — không ra internet |

## Chỉ rời máy khi bạn BẬT tính năng tương ứng (opt-in)
| Tính năng | Gửi gì ra ngoài | Tới đâu | Cách tắt |
|---|---|---|---|
| **AI đám mây** (Claude API / Bedrock / OpenAI / OpenRouter) ở chế độ `hybrid`/`cloud_only` | Finding + ngữ cảnh code quanh lỗ (đã **redact secret + PII**) | Nhà cung cấp AI bạn chọn | Để `mode=local_only` (mặc định) |
| **Pentest Agent dùng cloud model** | Output công cụ (đã redact secret + PII) đưa vào prompt | Nhà cung cấp AI | Dùng model local (Ollama) cho Pentest Agent |
| **Threat intel feeds** (EPSS/CISA KEV) | Chỉ tải feed công khai về, **không gửi dữ liệu của bạn đi** | FIRST / CISA | Dùng cache offline |
| **Connector XDR/NAC** | Truy vấn tới hệ thống bạn khai báo (theo cấu hình của bạn) | Server bạn nhập | Không thêm connector |
| **Gửi báo cáo tự động (SMTP)** | Báo cáo PDF + tóm tắt | Mail server bạn cấu hình | Không bật lịch/email |

## Redaction trước khi gửi cloud
Khi gửi ra AI đám mây, VulnGuard tự động che:
- **Secret**: private key, AWS key, `sk-...`, GitHub/Slack token, JWT, và gán kiểu `password=…`.
- **PII tiếng Việt / nội bộ**: CCCD/CMND, số điện thoại VN, email, IP nội bộ (10.x, 192.168.x, 172.16–31.x, 127.x, 169.254.x).

> Redaction là lớp phòng vệ, **không đảm bảo tuyệt đối**. Với dữ liệu nhạy cảm cao, hãy giữ
> `mode=local_only`.

## Mặc định an toàn
- App nghe `127.0.0.1` (localhost) — mở ra ngoài phải chủ động đặt `VULNGUARD_HOST=0.0.0.0`.
- Quét chủ động (web/crawl/pentest) bị khoá khi `AUTH_ENABLED=false`.
- Mật khẩu ADMIN không in ra màn hình; lưu file `storage/admin_credentials.txt` (chmod 600),
  bắt đổi lần đăng nhập đầu.
