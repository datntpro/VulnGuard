# SCM Integration (GitHub / GitLab)

Kết nối **GitHub** và **GitLab** (cloud hoặc self-managed / GitHub Enterprise qua `base_url`) để quét repo, đặt lịch quét và gửi báo cáo cho owner. Token được mã hoá Fernet trong DB và không hiển thị lại. Mã nguồn: `api/routes/scm.py`, `api/services/scm_service.py`, `api/services/scheduler.py`, `api/services/mailer.py`, `scanner/scm/providers.py`.

## Thiết lập (trang "Nguồn mã (SCM)")

1. **Thêm kết nối**: chọn GitHub/GitLab, nhập Base URL (để trống = cloud) và Personal Access Token. Nút **Test** kiểm tra token.
2. **Duyệt repo**: nút "Repo" liệt kê repo token đọc được, "+ Thêm" để chọn quét. Mỗi repo có `default_branch` (mặc định `main`), `owner_email`, `scan_types` (để trống = `SAST`, `SCA`, `SECRETS`, `IAC`) và `run_ai`.
3. **Quét ngay**: `git clone --depth 1 --single-branch --branch <branch>` (lỗi thì thử lại nhánh mặc định) vào thư mục tạm `vgscm_*` trong `SCAN_WORKSPACE` (không đặt thì thư mục temp của hệ thống), tạo Project/Scan rồi chạy orchestrator. Thư mục tạm bị xoá sau khi quét. Token được redact khỏi log và thông báo lỗi. "Quét ngay" **không** gửi email.
4. **Lịch quét**: `interval_minutes` (mặc định 1440, tối thiểu 5), `email_report` (mặc định bật), `enabled`.

## Scheduler

- Vòng lặp asyncio trong app, kiểm tra lịch đến hạn **mỗi 60 giây**. Lịch đang `RUNNING` được bỏ qua để tránh chạy trùng; `next_run_at` được đặt trước khi chạy.
- Bật/tắt bằng `VULNGUARD_SCHEDULER` (`1/true/yes/on` hoặc `0/false/no/off`). Không đặt thì bật khi `APP_ENV=production` (mặc định của `APP_ENV` là `production`).
- Chỉ chạy khi app đang chạy; không có worker riêng.

## SMTP (gửi báo cáo)

Cấu hình ở Settings: host, port, user, password, from (lưu trong `storage/runtime_settings.json`, mật khẩu mã hoá Fernet). Port 465 dùng SSL; port khác dùng `SMTP` và STARTTLS nếu bật. Nút **Gửi thử** gọi `POST /api/settings/smtp/test`.

Sau mỗi lần quét theo lịch có `email_report=true` và repo có `owner_email`, VulnGuard gửi email tóm tắt số lỗi theo mức độ, đính kèm PDF `vulnguard_<project>_<scan_number>.pdf`.

## Yêu cầu

- `git` trên máy chủ (đã có trong Docker image).
- Token phải đọc được repo cần quét. Code không kiểm tra scope cụ thể; gợi ý tối thiểu: GitHub fine-grained token quyền **Contents: Read** (hoặc classic `repo` cho repo private), GitLab `read_api` + `read_repository`.

## API

| Method | Path | Mô tả |
|---|---|---|
| GET / POST | `/api/scm/connections` | Liệt kê / tạo kết nối |
| DELETE | `/api/scm/connections/{conn_id}` | Xoá |
| POST | `/api/scm/connections/{conn_id}/test` | Test token |
| GET | `/api/scm/connections/{conn_id}/remote-repos` | Repo token đọc được |
| GET / POST | `/api/scm/repos` | Repo đã chọn / thêm repo |
| DELETE | `/api/scm/repos/{repo_id}` | Bỏ repo |
| POST | `/api/scm/repos/{repo_id}/scan-now` | Quét ngay (chạy nền) |
| GET / POST | `/api/scm/schedules` | Liệt kê / tạo lịch |
| PUT / DELETE | `/api/scm/schedules/{sch_id}` | Sửa / xoá lịch |

> Các endpoint `/api/scm/*` **không** giới hạn ADMIN: mọi ANALYST đều tạo/xoá được kết nối và token. Xem [[Security and Known Limitations|Security-and-Known-Limitations]].
