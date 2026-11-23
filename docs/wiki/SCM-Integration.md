# SCM Integration

Kết nối **GitHub** và **GitLab** (cloud *và* self-managed/onprem) để quét repo, đặt lịch quét và gửi báo cáo tự động cho owner. Token mã hoá, không hiển thị lại.

## Thiết lập (trang "Nguồn mã (SCM)")
1. **Thêm kết nối**: chọn GitHub/GitLab, nhập Base URL (trống = cloud) + Personal Access Token. Nút **Test** xác minh token.
2. **Duyệt repo**: nút "📂 Repo" liệt kê repo bạn có quyền → "+ Thêm" để chọn quét; nhập **email owner** nhận báo cáo.
3. **Quét ngay**: nút "▶ Quét ngay" clone repo (shallow, token redact) → tạo Project/Scan → chạy orchestrator.
4. **Lịch quét**: đặt chu kỳ (phút) + bật "gửi report owner" + "bật lịch". Scheduler nội bộ chạy đến hạn, chống chạy trùng.

## SMTP (gửi báo cáo)
Cấu hình host/port/user/password/from ở mục SMTP cùng trang. Nút **Gửi thử** để kiểm tra. Sau mỗi lần quét theo lịch, báo cáo PDF + tóm tắt mức độ được gửi tới `owner_email`.

## Yêu cầu
- `git` có sẵn (đã nằm trong Docker image).
- Scheduler bật theo `APP_ENV=production` hoặc `VULNGUARD_SCHEDULER=1`.
- Token GitHub: `repo` (read). GitLab: `read_api` + `read_repository`.
