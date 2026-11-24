# MCP Server

`mcp_server/server.py` expose dữ liệu asset inventory, threat intel (EPSS/KEV) và ngữ cảnh XDR/EDR/NAC của VulnGuard dưới dạng MCP tools, cho Claude Desktop hoặc agent khác truy vấn. Server đọc cùng database với app chính (`DATABASE_URL`). Phụ thuộc: gói `mcp>=2.0.0` (có trong `api/requirements.txt`).

## Tools

Tất cả tool đều **read-only**.

| Tool | Tham số | Trả về |
|---|---|---|
| `query_assets` | `min_risk=0`, `source` (vd `fortinac`, `trellix`), `limit=50` | Danh sách asset sắp theo risk giảm dần: hostname, ip, risk_score, risk_band, active_alerts, exposure, sources |
| `get_asset` | `host_or_ip` (hostname / IP / MAC) | Chi tiết asset: OS, criticality, exposure, risk_factors, vulns (CVE, CVSS, EPSS, KEV), alerts |
| `host_edr_context` | `host_or_ip` | Có agent EDR không, edr_health, nac_status, vlan, số alert đang hoạt động, kỹ thuật ATT&CK |
| `cve_intel` | `cve` | EPSS + CISA KEV cho 1 CVE |
| `asset_risk_summary` | | Tổng asset, số asset theo band, top 10 risk |
| `list_connectors` | | Connector XDR/EDR/NAC đã cấu hình + trạng thái sync gần nhất (không trả secret) |
| `request_isolate_host` | `host_or_ip`, `reason` | **Không thực thi.** Chỉ trả `executed: false`, `requires_approval: true` |

## Chạy

Từ thư mục gốc repo, trong venv của app:

### stdio (Claude Desktop)

```bash
python -m mcp_server.server
```

Ví dụ cấu hình Claude Desktop (điều chỉnh đường dẫn):

```json
{
  "mcpServers": {
    "vulnguard": {
      "command": "/path/to/VulnGuard/.venv/bin/python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/VulnGuard"
    }
  }
}
```

### HTTP (streamable HTTP)

```bash
export VULNGUARD_MCP_TOKEN="<chuỗi ngẫu nhiên dài>"
python -m mcp_server.server --http --host 127.0.0.1 --port 8899
```

- `--host` mặc định `127.0.0.1`, `--port` mặc định `8899`.
- Không có `VULNGUARD_MCP_TOKEN` thì server **từ chối chạy** (fail-closed).
- Mỗi request phải gửi `Authorization: Bearer <token>`; sai hoặc thiếu trả `401`.
- Nếu phiên bản MCP SDK không expose ASGI app để bọc xác thực, server thoát thay vì chạy HTTP không bảo vệ. Khi đó dùng stdio hoặc đặt reverse proxy có auth phía trước.

## Lưu ý

- MCP server không dùng cơ chế đăng nhập/RBAC của web app; ai có token (HTTP) hoặc chạy được process (stdio) đều đọc được toàn bộ inventory.
- Chỉ bind ra ngoài `127.0.0.1` khi có TLS/reverse proxy phía trước, vì bearer token đi dạng plaintext qua HTTP.
- Pentest Agent không gọi MCP server; tool `asset_context` của agent đọc thẳng database.
