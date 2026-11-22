"""
VulnGuard MCP server — expose Asset inventory, threat intel (EPSS/KEV) và ngữ cảnh
XDR/EDR/NAC dưới dạng MCP tools, để:
  - Pentest/Triage Agent (Claude) gọi như tool khi đang chạy ("host này EDR có báo không?").
  - Claude Desktop / agent bên thứ ba truy vấn dữ liệu VulnGuard.

Chạy:
  stdio (Claude Desktop):   python -m mcp_server.server
  HTTP (agent qua URL):     python -m mcp_server.server --http --port 8899
(đọc DATABASE_URL như app chính).

An toàn: toàn bộ tool ở đây là READ-ONLY. Hành động phá huỷ (cô lập host) KHÔNG
expose để tự chạy — tool request_isolate_host chỉ trả hướng dẫn, việc cô lập thật
phải qua approval gate của Pentest Agent.
"""
import os
from typing import Optional

from mcp.server.mcpserver import MCPServer

mcp = MCPServer(name="vulnguard",
                instructions="Truy vấn asset inventory, risk score, EPSS/KEV và ngữ cảnh XDR/EDR/NAC của VulnGuard. Tất cả read-only.")


def _db():
    from api.database import SessionLocal
    return SessionLocal()


def _find_asset(db, q: str):
    from api.asset_models import Asset
    from sqlalchemy import func
    ql = q.lower()
    return (db.query(Asset).filter((func.lower(Asset.hostname) == ql) | (Asset.ip == q) |
                                   (func.lower(Asset.mac) == ql)).first())


@mcp.tool()
def query_assets(min_risk: float = 0, source: Optional[str] = None, limit: int = 50) -> list:
    """Liệt kê asset, lọc theo risk tối thiểu và/hoặc nguồn (fortinac/trellix/...), sắp theo risk giảm dần."""
    from api.asset_models import Asset
    from scanner.assets.scoring import band
    db = _db()
    try:
        rows = db.query(Asset).all()
        if source:
            rows = [a for a in rows if source in (a.sources or [])]
        rows = [a for a in rows if (a.risk_score or 0) >= min_risk]
        rows.sort(key=lambda a: a.risk_score or 0, reverse=True)
        return [{"hostname": a.hostname, "ip": a.ip, "risk_score": a.risk_score,
                 "risk_band": band(a.risk_score or 0), "active_alerts": a.active_alert_count,
                 "exposure": a.exposure.value if a.exposure else None, "sources": a.sources or []}
                for a in rows[:limit]]
    finally:
        db.close()


@mcp.tool()
def get_asset(host_or_ip: str) -> dict:
    """Chi tiết 1 asset (vuln, alert, software, risk factors) theo hostname/ip/mac."""
    db = _db()
    try:
        a = _find_asset(db, host_or_ip)
        if not a:
            return {"found": False}
        return {"found": True, "hostname": a.hostname, "ip": a.ip, "os": a.os,
                "criticality": a.criticality.value if a.criticality else None,
                "exposure": a.exposure.value if a.exposure else None,
                "risk_score": a.risk_score, "risk_factors": a.risk_factors or {},
                "active_alert_count": a.active_alert_count, "edr_agent_present": a.edr_agent_present,
                "vulns": [{"cve": v.cve, "cvss": v.cvss_score, "epss": v.epss, "kev": v.kev,
                           "risk_score": v.risk_score} for v in a.vulns],
                "alerts": [{"title": al.title, "severity": al.severity, "status": al.status,
                            "technique": al.technique, "source": al.source} for al in a.alerts]}
    finally:
        db.close()


@mcp.tool()
def host_edr_context(host_or_ip: str) -> dict:
    """Ngữ cảnh phòng thủ của host: có agent EDR không, số alert đang hoạt động, kỹ thuật ATT&CK.
    Hữu ích cho pentest để biết host có đang bị giám sát / đã bị tấn công thật."""
    db = _db()
    try:
        a = _find_asset(db, host_or_ip)
        if not a:
            return {"found": False}
        active = [al for al in a.alerts if (al.status or "").lower() not in ("closed", "resolved")]
        return {"found": True, "hostname": a.hostname, "edr_agent_present": a.edr_agent_present,
                "edr_health": a.edr_health, "nac_status": a.nac_status, "vlan": a.vlan,
                "active_alerts": len(active),
                "techniques": sorted({al.technique for al in active if al.technique}),
                "sources": a.sources or []}
    finally:
        db.close()


@mcp.tool()
def cve_intel(cve: str) -> dict:
    """Tra EPSS (xác suất bị khai thác) + CISA KEV (đang bị khai thác thật) cho 1 CVE."""
    from scanner.intel.feeds import enrich
    return enrich(cve)


@mcp.tool()
def asset_risk_summary() -> dict:
    """Thống kê rủi ro toàn bộ inventory + top asset rủi ro cao nhất."""
    from api.asset_models import Asset
    from scanner.assets.scoring import band
    db = _db()
    try:
        rows = db.query(Asset).all()
        bands = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for a in rows:
            bands[band(a.risk_score or 0)] += 1
        top = sorted(rows, key=lambda a: a.risk_score or 0, reverse=True)[:10]
        return {"total": len(rows), "by_band": bands,
                "top_risk": [{"hostname": a.hostname, "risk_score": a.risk_score} for a in top]}
    finally:
        db.close()


@mcp.tool()
def list_connectors() -> list:
    """Danh sách connector XDR/EDR/NAC đã cấu hình + trạng thái sync gần nhất (không lộ secret)."""
    from api.connector_models import ConnectorConfig
    db = _db()
    try:
        return [{"name": c.name, "kind": c.kind.value if c.kind else None, "enabled": c.enabled,
                 "last_sync_at": str(c.last_sync_at) if c.last_sync_at else None,
                 "last_sync_status": c.last_sync_status, "stats": c.last_sync_stats}
                for c in db.query(ConnectorConfig).all()]
    finally:
        db.close()


@mcp.tool()
def request_isolate_host(host_or_ip: str, reason: str) -> dict:
    """Yêu cầu cô lập 1 host qua NAC/EDR. KHÔNG tự thực thi — hành động phá huỷ phải được
    con người duyệt trong VulnGuard (Pentest Agent approval). Tool này chỉ ghi nhận ý định."""
    return {"executed": False, "requires_approval": True,
            "message": f"Yêu cầu cô lập {host_or_ip} ('{reason}') cần người duyệt trong VulnGuard — không tự thực thi qua MCP."}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--http", action="store_true", help="Chạy streamable HTTP thay vì stdio")
    ap.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()
    if args.http:
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
