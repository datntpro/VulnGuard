# Features

## Quét bảo mật (SAST/SCA/IaC/Container/Secrets/DAST)
- Chạy song song nhiều scanner, **dedup theo fingerprint**, gộp finding cùng lỗi từ nhiều tool.
- SAST đa ngôn ngữ: chọn ruleset theo ngôn ngữ phát hiện (Python, JS/TS, React, Node, Java, Go, PHP, Ruby).
- Secrets: hạ mức false positive cho file test/fixture và giá trị công khai (OAuth Client ID…).
- Crawl bằng **Katana** (xuất JSON, sitemap XML, WAF baseline, rule ModSecurity) và web scan **Nuclei** + **kiểm thiếu security header** native (HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy). Bắt buộc xác minh quyền sở hữu domain.
- **Tính trung thực**: tool thiếu/không chạy được → báo **"bỏ qua"**, không im lặng trả "0 lỗi".

## Knowledge Base (tri thức lỗ hổng)
- DB lỗ hổng nguồn mở (**OSV + EPSS + CISA KEV**) build hằng ngày qua CI, phân phối kiểu **Trivy DB**: máy đã cài tự tải snapshot ký `sha256`, verify và hoán đổi nguyên khối; hỗ trợ **import offline/air-gap**.
- **Làm giàu** finding: fix version, CWE, CVSS, tham chiếu.
- **Tự nâng ưu tiên**: trong CISA KEV → tối thiểu HIGH (ransomware → CRITICAL); EPSS ≥ 0.5 → tối thiểu HIGH. Badge 🔥 KEV / 💀 Ransomware / EPSS % trên UI và báo cáo.
- Local-first: chỉ tải dữ liệu công khai về, không gửi dữ liệu máy bạn đi. Chi tiết: [[Knowledge Base|Knowledge-Base]].

## Quản lý lỗ hổng kiểu Checkmarx
- **Triage states**: To Verify / Confirmed / Urgent / Proposed Not Exploitable / Not Exploitable / Accepted / Fixed.
- **Kế thừa triage qua scan**: finding đã triage không phải đánh lại.
- **Audit trail** đổi trạng thái (change log xuyên scan); chỉ ADMIN chốt "Not Exploitable".
- **Scan History + xu hướng** + so sánh 2 scan (New / Recurring / Resolved / **Not Evaluated**).
- **Đồ thị data-flow** source→sink (Semgrep taint).

## Báo cáo & export
- **PDF** chuẩn doanh nghiệp (bìa, kết luận rủi ro, bảng, header/footer, tiếng Việt), logo tùy chỉnh.
- **SARIF 2.1.0** (cắm GitHub Code Scanning / GitLab / Azure DevOps), Markdown, JSON, CSV, AI-JSON.
- Lọc báo cáo theo New/Recurrent/active.

## Compliance
Ánh xạ mỗi finding → **OWASP Top 10 2021, ISO/IEC 27001:2022, TCVN 11930:2017 / NĐ 85, PCI-DSS 4.0**; tab Tuân thủ với điểm theo từng khung.

## Tích hợp SCM & tự động hoá
- Kết nối **GitHub & GitLab** (cloud + self-managed/onprem), duyệt repo.
- **Quét theo lịch** + **gửi báo cáo PDF tự động** cho owner qua SMTP.

## Pentest Agent (có kiểm soát)
- Agent tool-use (Claude) trong **scope** khai báo; risk gate (RECON/ACTIVE_SAFE/INTRUSIVE/DESTRUCTIVE).
- Scope gate theo rule `domain` / `ip` / `cidr` / `url` (allow/deny), phân giải DNS ngay trước khi chạy tool, chặn IP nội bộ/loopback/metadata trừ khi khai báo tường minh bằng ip/cidr.
- Bằng chứng: recording MITM proxy (CA tự sinh), replay request trong scope.
- Tách quyền: chỉ ADMIN được uỷ quyền engagement; người khởi chạy run không tự duyệt hành động của mình, người duyệt (ADMIN hoặc ANALYST khác) phải ghi lý do.

## Tài sản & rủi ro
- Asset inventory (dedup theo mac|hostname|ip), **risk theo ngữ cảnh** (CVSS×EPSS×KEV×criticality×exposure).
- Threat intel: EPSS (FIRST) + CISA KEV, cache offline.
- Connector XDR/EDR/NAC (Trellix XDR, Trend Micro Vision One, FortiNAC) + [[MCP server|MCP-Server]] read-only.

## AI
Ollama local hoặc cloud (Claude/Bedrock/OpenAI/OpenRouter/Azure OpenAI/Gemini/Vertex): giảm false positive, giải thích + gợi ý fix tiếng Việt. Cấu hình ở Settings › AI; mỗi người có thể dùng khoá riêng. Xem [[Per-user AI keys|AI-Per-User-Keys]] và [[Kiro: Bedrock via IAM Identity Center|AI-Kiro-Bedrock-IAM-Identity-Center]]. Pentest Agent cần model có tool-calling (đã qua probe).

## Module phụ (tắt được bằng feature flag)
- **Document Review**: review tài liệu SRS/HLD/API spec theo checklist OWASP ASVS bằng Ollama, có version và so sánh version.
- **File Assistant**: chat với file bằng Ollama.
- **Co-work**: AI đề xuất sửa code; đọc/ghi file và chạy lệnh qua `coworker_host` (chỉ ADMIN, người dùng xác nhận trên UI).
