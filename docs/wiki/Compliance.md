# Compliance

VulnGuard ánh xạ mỗi lỗ hổng sang các khung tuân thủ, phục vụ audit — **không thay văn bản gốc**.

## Khung hỗ trợ
- **OWASP Top 10 2021** (ánh xạ theo CWE).
- **ISO/IEC 27001:2022** (Annex A controls).
- **TCVN 11930:2017 / Nghị định 85/2016** (nhóm kiểm soát an toàn theo cấp độ).
- **PCI-DSS v4.0**.

## Tab Tuân thủ
Tổng hợp toàn hệ thống (hoặc theo project): mỗi khung có **điểm/100** + bảng nhóm kiểm soát với số phát hiện, mức nặng nhất, trạng thái **ĐẠT / KHÔNG ĐẠT / CẢNH BÁO** (KHÔNG ĐẠT = có lỗ hổng Cao/Nghiêm trọng).

## SARIF export
Xuất **SARIF 2.1.0** (`format=sarif`) để cắm thẳng GitHub Code Scanning / GitLab / Azure DevOps — rule kèm `security-severity` + tag OWASP/ISO/TCVN/CWE.

## Chuẩn chấm điểm quốc tế dùng sẵn
CVSS v3.1 (severity), EPSS (xác suất khai thác), CISA KEV (đang bị khai thác), CWE, CVE/NVD.
