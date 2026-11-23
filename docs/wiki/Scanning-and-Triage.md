# Scanning & Triage

## Luồng quét
1. Tạo Project → trỏ đường dẫn mã nguồn (hoặc quét repo qua [SCM](SCM-Integration)).
2. Chọn loại quét (SAST/SCA/IaC/Container/Secrets) + bật AI analysis (tùy chọn).
3. Scanner chạy **song song**, dedup theo fingerprint; kết quả hiện ngay, AI triage chạy nền.
4. Mục **"Công cụ đã dùng"** liệt kê mọi tool + trạng thái (chạy / 0 lỗi / **bỏ qua** / lỗi) — minh bạch, "0 lỗi" chỉ đúng khi mọi tool thật sự chạy.

## Triage (kiểu Checkmarx)
Trạng thái: **Cần xác minh (To Verify)** → **Đã xác nhận / Khẩn cấp** · **Đề xuất không khai thác được** · **Không khai thác được** (chỉ ADMIN chốt) · **Chấp nhận** · **Đã sửa**.
- Note **bắt buộc** khi chuyển sang Không khai thác được / Chấp nhận.
- **Audit trail**: mọi thay đổi ghi lại (ai, khi nào, từ gì → gì) — xuyên scan theo fingerprint.
- **Kế thừa qua scan**: finding đã triage ở scan trước tự giữ trạng thái, không phải đánh lại.
- Badge **Mới / Tái xuất hiện** trên từng finding.

## Lịch sử & so sánh scan
- Trang Project có **biểu đồ xu hướng** severity qua các lần scan.
- Chọn 2 scan → so sánh: **Mới (New) / Tái xuất hiện (Recurring) / Đã khắc phục (Resolved) / Chưa đánh giá (Not Evaluated)**.
- "Not Evaluated" = finding thuộc loại quét không chạy lại (settings đổi) → không báo nhầm "đã fix".

## Đồ thị data-flow
Với finding Semgrep taint-mode: xem đường đi **nguồn (source) → lan truyền → đích (sink)** kèm `file:line` + đoạn code từng bước.
