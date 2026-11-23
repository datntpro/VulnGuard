# Features

## Quét bảo mật (SAST/SCA/IaC/Container/Secrets/DAST)
- Chạy song song nhiều scanner, **dedup theo fingerprint**, gộp finding cùng lỗi từ nhiều tool.
- SAST đa ngôn ngữ: chọn ruleset theo ngôn ngữ phát hiện (Python, JS/TS, React, Node, Java, Go, PHP, Ruby).
- Secrets: hạ mức false positive cho file test/fixture và giá trị công khai (OAuth Client ID…).
- Web scan (Nuclei) + **kiểm thiếu security header** native (HSTS/CSP/X-Frame-Options…).
- **Tính trung thực**: tool thiếu/không chạy được → báo **"bỏ qua"**, không im lặng trả "0 lỗi".

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
- Scope gate phân giải DNS, chặn IP nội bộ/metadata (chống SSRF/rebinding).
- Tách quyền: người chạy không tự duyệt; hành động rủi ro cần ADMIN phê duyệt + ghi lý do.

## Tài sản & rủi ro
- Asset inventory (dedup theo mac|hostname|ip), **risk theo ngữ cảnh** (CVSS×EPSS×KEV×criticality×exposure).
- Threat intel: EPSS (FIRST) + CISA KEV, cache offline.
- Connector XDR/NAC (Trellix, Trend Vision One, FortiNAC) + MCP server.

## AI
Ollama local hoặc cloud (Claude/Bedrock/OpenAI/OpenRouter) — giảm false positive, giải thích + gợi ý fix tiếng Việt.
