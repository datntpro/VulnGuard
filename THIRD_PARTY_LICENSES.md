# Giấy phép bên thứ ba (Third-party licenses)

VulnGuard gọi/đóng gói các công cụ và bộ rule bên thứ ba. Mỗi thứ giữ giấy phép riêng của
nó. Danh sách dưới đây để rà soát tuân thủ — **cần kiểm tra lại trước khi phân phối thương mại**
(đặc biệt lưu ý tương thích với AGPL-3.0 và việc đóng gói binary).

| Công cụ | Vai trò | Giấy phép (cần xác nhận) | Lưu ý |
|---|---|---|---|
| Semgrep (CLI) | SAST | LGPL-2.1 (CLI); rule registry theo giấy phép riêng | Rule `p/*` có điều khoản riêng — rà trước khi bán |
| Bandit | SAST Python | Apache-2.0 | |
| Trivy | SCA/IaC/Container | Apache-2.0 | |
| pip-audit | SCA Python | Apache-2.0 | |
| detect-secrets | Secrets | Apache-2.0 | |
| Gitleaks | Secrets | MIT | |
| Checkov | IaC | Apache-2.0 | |
| Grype / Syft | Container/SBOM | Apache-2.0 | |
| Hadolint | Dockerfile | GPL-3.0 | Chỉ gọi binary, không link |
| Nuclei | DAST | MIT; **template** theo giấy phép riêng của ProjectDiscovery | Rà điều khoản dùng template |
| Katana | Crawler | MIT | |
| nmap | Recon (Pentest Agent) | **NPSL** (gần GPL, có hạn chế) | KHÔNG đóng gói lại; chỉ gọi nếu người dùng tự cài |
| sqlmap | Pentest | GPL-2.0 | Chỉ gọi khi được uỷ quyền + duyệt |
| SonarQube Community | SAST server | LGPL-3.0 | Chạy tách như service |
| SecLists | Wordlist | nhiều giấy phép | Rà từng danh sách |
| FIRST CVSS v4.0 calculator (github.com/FIRSTdotorg/cvss-v4-calculator, RedHatProductSecurity/cvss-v4-calculator) | Chấm điểm CVSS v4 (Pentest Agent) | BSD-2-Clause, © 2023 FIRST.ORG, Inc., Red Hat, and contributors | Bảng dữ liệu + thuật toán được port vào `scanner/pentest/{cvss4_data,scoring}.py`; giữ nguyên notice trong header file |
| Typst (qua gói Python `typst` / typst-py 0.15.2, lõi Typst 0.15.1) | Engine dựng PDF báo cáo (`scanner/pdf`) | Apache-2.0 | Chạy trong worker subprocess, không mạng, không package `@preview`; giữ NOTICE của Typst khi phân phối |
| Be Vietnam Pro (Be Vietnam Pro Project Authors) | Font báo cáo PDF (400/500/600/700/800 + Italic) | SIL OFL 1.1 | Đóng gói trong `scanner/pdf/templates/fonts/`; văn bản giấy phép: `OFL-BeVietnamPro.txt` |
| JetBrains Mono v2.304 (JetBrains Mono Project Authors) | Font monospace cho code/evidence trong PDF | SIL OFL 1.1 | Văn bản giấy phép: `OFL-JetBrainsMono.txt` |
| DejaVu Sans (Bitstream Vera / DejaVu) | Font dự phòng ký hiệu trong PDF (và PDF "nhanh" fpdf2 ở `scanner/assets/fonts`) | Bitstream Vera License (cho phép tự do phân phối) | Văn bản: `scanner/pdf/templates/fonts/LICENSE-DejaVu.txt` |

## Hành động cần làm (P0.11)
- [ ] Luật sư/kỹ thuật xác nhận từng dòng giấy phép ở trên theo phiên bản thực tế đang dùng.
- [ ] Với bản Pro (thương mại): xác nhận không đóng gói lại tool GPL/NPSL theo cách vi phạm;
      ưu tiên "gọi binary người dùng tự cài" thay vì bundle.
- [ ] Ghi rõ trong tài liệu sản phẩm công cụ nào bắt buộc, công cụ nào tùy chọn.

_Bảng này là điểm khởi đầu rà soát, không phải kết luận pháp lý._
