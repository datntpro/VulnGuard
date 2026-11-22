# Connectors (XDR/EDR/NAC) + Asset Inventory + Risk Scoring + MCP

Biến VulnGuard thành **context-aware vulnerability management**: kéo dữ liệu từ
hệ thống phòng thủ sẵn có (XDR/EDR/NAC) để chấm điểm rủi ro sát thực tế hơn
Tenable/Nexpose trong chính môi trường của bạn.

## Asset inventory + Risk scoring
- `Asset` dedup theo mac → hostname → ip (NAC cho mac+hostname, EDR cho hostname → gộp 1 máy).
- **Risk score (0..100) giải thích được**: `100 · (cvss/10) · (0.2+0.8·threat) · context`
  - `threat` = EPSS; CVE trong CISA KEV ⇒ threat = 1.0
  - `context` = (trọng số criticality + trọng số exposure)/2
  - Asset risk = max điểm vuln, cộng thêm khi có **alert EDR đang hoạt động** (đang bị tấn công thật).
- Cùng 1 CVE: máy critical/internet có thể 100đ, máy low/isolated chỉ ~6đ.
- API: `/api/assets` (sort risk), `/api/assets/summary`, `/api/assets/{id}`, PATCH criticality/exposure.
- Threat intel: `/api/intel/status`, `/api/intel/refresh` (EPSS từ FIRST + KEV từ CISA, cache offline).

## Connectors
| Kind | Hãng | Auth | Lấy gì |
|---|---|---|---|
| `TRELLIX_XDR` | Trellix XDR/EDR | OAuth2 client credentials | device inventory, detection/alert |
| `TRENDMICRO_VISION_ONE` | Trend Micro Vision One | Bearer API token | endpoint inventory, workbench alert |
| `FORTINAC` | FortiNAC | username/password → token | host inventory, VLAN/port → exposure |

- Secret **mã hoá Fernet**, API chỉ trả hint (vd `…et`), không bao giờ lộ raw.
- Đường dẫn endpoint **cấu hình được** (mỗi deployment hơi khác) — xem `config_fields` của từng kind (`GET /api/connectors/kinds`).
- API (ADMIN): CRUD `/api/connectors`, `POST /{id}/test`, `POST /{id}/sync`.
- Sync: kéo asset+alert+software → upsert inventory → recompute risk.
- **Mở rộng vendor khác** chỉ cần viết 1 adapter kế thừa `BaseConnector` + đăng ký trong `registry.py`.

## MCP server
Expose inventory + intel + ngữ cảnh XDR/EDR/NAC dưới dạng **MCP tools** (read-only):
`query_assets`, `get_asset`, `host_edr_context`, `cve_intel`, `asset_risk_summary`,
`list_connectors`, `request_isolate_host` (chỉ ghi nhận — cô lập thật phải qua approval).

Chạy:
```bash
# stdio — cho Claude Desktop (thêm vào mcpServers config)
python -m mcp_server.server
# HTTP — cho agent gọi qua URL
python -m mcp_server.server --http --port 8899
```
Pentest/Triage Agent (Claude API) gắn qua MCP connector (`mcp_servers` + `mcp_toolset`),
hoặc dùng trực tiếp tool nội bộ **`asset_context`** đã tích hợp sẵn trong Pentest Agent
(đọc ngữ cảnh EDR/NAC của host khi đang kiểm thử, read-only, miễn scope gate).

## An toàn
- Tool đọc: tự do. Hành động phá huỷ (cô lập host qua NAC/EDR): **DESTRUCTIVE** → phải qua approval gate của Pentest Agent, không tự chạy qua MCP.
- Connector chỉ ADMIN cấu hình. Credential mã hoá at-rest.
