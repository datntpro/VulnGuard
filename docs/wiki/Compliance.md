# Compliance

VulnGuard ánh xạ mỗi lỗ hổng code sang các khung tuân thủ để hỗ trợ định hướng audit. Đây **không** phải đánh giá tuân thủ đầy đủ và không thay văn bản gốc. Mã nguồn: `scanner/compliance.py`, endpoint `GET /api/dashboard/compliance`.

## Khung hỗ trợ

| Key | Khung |
|---|---|
| `owasp` | OWASP Top 10 (2021) |
| `iso27001` | ISO/IEC 27001:2022 (Annex A) |
| `tcvn11930` | TCVN 11930:2017 / NĐ 85/2016 (tên nhóm kiểm soát mô tả, không trích điều khoản cụ thể) |
| `pci_dss` | PCI-DSS v4.0 |

## Cách ánh xạ

Trục xoay là **OWASP Top 10 2021**:

1. Finding có CWE nằm trong danh mục CWE của OWASP Top 10 2021 thì lấy hạng mục đó.
2. Không khớp CWE nhưng có CVE: `A06` (Vulnerable and Outdated Components).
3. Còn lại suy theo loại quét: `SCA`/`CONTAINER` → `A06`, `SECRETS` → `A07`, `IAC`/`DAST` → `A05`, `SAST` → `A03`; mặc định `A05`.
4. Từ hạng mục OWASP suy ra control ISO 27001, nhóm TCVN và yêu cầu PCI-DSS theo bảng cố định. Ví dụ `A03` → ISO `A.8.28 Secure coding`, TCVN `AT.UD-MN`, PCI `Req 6.2`.

## Tab Tuân thủ và cách chấm điểm

`GET /api/dashboard/compliance?project_id=` (bỏ `project_id` để lấy toàn hệ thống).

- Dữ liệu: chỉ **lỗ hổng code đang mở** (`OPEN`, `CONFIRMED`, `URGENT`, `PROPOSED_NE`) của mọi scan (hoặc mọi scan của project). Finding web scan, pentest và asset không được tính.
- Chỉ liệt kê control **bị chạm tới** (có ít nhất 1 finding). Không có trạng thái "ĐẠT" cho từng control.
- Trạng thái control:
  - **KHÔNG ĐẠT**: finding nặng nhất là `HIGH` hoặc `CRITICAL`.
  - **CẢNH BÁO**: finding nặng nhất là `MEDIUM`, `LOW` hoặc `INFO`.
- Điểm khung = `100 × (số control bị chạm − số KHÔNG ĐẠT) / số control bị chạm`. Không có finding nào thì điểm 100 (nghĩa là "không phát hiện vi phạm trong phạm vi quét", không phải chứng nhận tuân thủ).

## Trong báo cáo

- **SARIF 2.1.0** (`GET /api/scans/{scan_id}/export?format=sarif`): mỗi rule có `security-severity` (CRITICAL 9.5, HIGH 7.5, MEDIUM 5.0, LOW 3.0, INFO 1.0) và tag `security`, `OWASP Axx`, `ISO A.x.x`, `TCVN ...` (và `external/cwe/cwe-N` nếu có CWE). Dùng được với GitHub Code Scanning, GitLab, Azure DevOps.
- PDF ghi tag OWASP/ISO/TCVN dưới mỗi finding và có bảng tóm tắt tuân thủ theo từng khung (tính trên các finding trong báo cáo).

## Chuẩn chấm điểm dùng sẵn

CVSS (severity từ tool), EPSS và CISA KEV (cho asset, xem [[Assets and Connectors|Assets-and-Connectors]]), CWE, CVE.
