# VulnGuard — Điều khoản sử dụng & Uỷ quyền quét (EULA)

> Áp dụng cho cả bản Community (AGPL-3.0) và Pro (thương mại). Bằng việc cài đặt hoặc
> sử dụng VulnGuard, bạn đồng ý với các điều khoản dưới đây.

## 1. Phạm vi cho phép
VulnGuard là công cụ **bảo mật phòng thủ**: quét lỗ hổng mã nguồn/phụ thuộc/hạ tầng,
quản lý lỗ hổng và kiểm thử **ĐÃ ĐƯỢC UỶ QUYỀN**.

## 2. Nghĩa vụ uỷ quyền (BẮT BUỘC) ⚠️
Các tính năng quét **chủ động** — Web Scan, Domain Crawl, và **Pentest Agent** — chỉ được
dùng trên hệ thống mà bạn **sở hữu hoặc có văn bản uỷ quyền hợp lệ**. Cụ thể bạn cam kết:
- Có quyền hợp pháp (sở hữu, hoặc thư uỷ quyền/hợp đồng) đối với mọi mục tiêu quét.
- Không dùng VulnGuard để quét, dò, tấn công hệ thống của bên thứ ba khi chưa được phép.
- Tuân thủ pháp luật sở tại về an toàn/an ninh mạng (ví dụ tại Việt Nam: Luật ATTT mạng,
  Luật An ninh mạng, và các nghị định liên quan).

VulnGuard yêu cầu **xác minh quyền sở hữu** mục tiêu (DNS TXT hoặc `/.well-known/vulnguard.txt`)
và lưu lại bằng chứng uỷ quyền trước khi cho phép quét chủ động.

## 3. Tách quyền & phê duyệt
Hành động rủi ro cao (INTRUSIVE/DESTRUCTIVE) cần người có thẩm quyền (ADMIN) phê duyệt;
người khởi chạy không được tự phê duyệt hành động của chính mình.

## 4. Miễn trừ trách nhiệm
PHẦN MỀM ĐƯỢC CUNG CẤP "NGUYÊN TRẠNG", KHÔNG BẢO HÀNH. Chủ sở hữu bản quyền không chịu
trách nhiệm cho thiệt hại phát sinh từ việc sử dụng, bao gồm việc quét trái phép do người
dùng thực hiện. **Người dùng tự chịu trách nhiệm pháp lý về phạm vi và đối tượng quét.**

## 5. Dữ liệu
Xem [`docs/DATA_FLOW.md`](./docs/DATA_FLOW.md) để biết dữ liệu nào ở lại máy và dữ liệu nào
có thể rời máy (khi bật tính năng AI đám mây).

---
_Đây không phải tư vấn pháp lý; cần luật sư rà soát trước khi phân phối thương mại._
