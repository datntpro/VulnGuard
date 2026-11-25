# FAQ

**VulnGuard chạy trên hệ điều hành nào?**
macOS và Linux (`setup.sh`, `run.sh`), Windows (`setup.ps1`, `run.ps1`), hoặc Docker (`docker compose`). Xem [[Installation]].

**Dữ liệu có rời khỏi máy không?**
Mặc định AI mode là `local_only` (chỉ Ollama), dữ liệu quét nằm trong SQLite ở `storage/`. Dữ liệu chỉ ra ngoài khi bạn bật `hybrid`/`cloud_only`, dùng Pentest Agent (luôn cần Anthropic hoặc Bedrock), cấu hình connector/SCM/SMTP, hoặc tải EPSS/KEV. Xem [[Security and Data Flow|Security-and-Data-Flow]].

**Tài khoản ADMIN đầu tiên ở đâu?**
`setup.sh` gọi `scripts/bootstrap_admin.py`: tạo ADMIN (mặc định `admin@vulnguard.local`, đổi bằng `ADMIN_EMAIL`) và ghi mật khẩu vào `storage/admin_credentials.txt` (chmod 600), không in ra màn hình. Đăng nhập, đổi mật khẩu, rồi xoá file. Nếu chưa có user nào (vd chạy Docker), trang đăng nhập cho tạo ADMIN đầu tiên — cần setup token trong `storage/setup_token` (hoặc `VULNGUARD_SETUP_TOKEN`).

**Quên mật khẩu thì sao?**
Code không có endpoint đặt lại mật khẩu: `PATCH /api/auth/users/{id}` chỉ đổi `name`, `role`, `is_active`; `POST /api/auth/change-password` cần mật khẩu hiện tại. Hãy giữ ít nhất 2 tài khoản ADMIN.

**Các vai trò khác nhau thế nào?**
`ADMIN` toàn quyền; `ANALYST` chạy scan, triage, quét web, pentest (trừ các thao tác chỉ ADMIN); `VIEWER` chỉ đọc. Xem [[Authentication and Roles|Authentication-and-Roles]].

**Có quét được website không phải của tôi không?**
Crawl và web scan yêu cầu xác minh quyền sở hữu domain (DNS TXT hoặc file `.well-known`). Pentest yêu cầu engagement được ADMIN uỷ quyền với scope rõ ràng, nhưng không kiểm tra quyền sở hữu domain. Trách nhiệm pháp lý thuộc về người dùng; chỉ quét tài sản bạn được phép.

**Vì sao kết quả có ít lỗi hơn mong đợi?**
Thường do tool chưa cài và bị `skipped`. Xem mục "Công cụ đã dùng" trong báo cáo và [[Troubleshooting]].

**Pentest Agent có tự khai thác không?**
Có thể chạy công cụ chủ động trong scope. Ở chế độ `AUTONOMOUS_IN_SCOPE`, RECON và ACTIVE_SAFE tự chạy; INTRUSIVE và DESTRUCTIVE luôn cần người khác duyệt. Ở `GUIDED`, chỉ RECON tự chạy. Xem [[Pentest Agent|Pentest-Agent]].

**Có tích hợp CI/CD được không?**
Có: export SARIF để đẩy lên GitHub Code Scanning, endpoint `approve-check` làm cổng phát hành, và repo có workflow `ci.yml`, `security.yml` làm mẫu. CLI hiện chưa gửi token nên không dùng được khi bật auth; gọi REST API với Bearer token.

**Giấy phép?**
Giấy phép kép: Community theo **AGPL-3.0-only** (`LICENSE`), Pro theo giấy phép thương mại (`COMMERCIAL-LICENSE.md`), kèm `EULA.md` và `THIRD_PARTY_LICENSES.md`. Nếu chạy bản đã sửa đổi như dịch vụ mạng, AGPL yêu cầu công khai mã nguồn bản đó.

**Báo lỗi hoặc góp ý ở đâu?**
Mở issue tại repo [datntpro/VulnGuard](https://github.com/datntpro/VulnGuard). Lỗi bảo mật nên báo riêng cho maintainer.
