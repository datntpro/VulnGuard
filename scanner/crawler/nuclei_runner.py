"""
Nuclei runner — quét lỗ hổng web (DAST) cho danh sách URL (thường lấy từ Katana crawl).

- Đọc stdout JSONL theo dòng → cập nhật progress realtime (số finding).
- Parser "tolerant": schema JSON nuclei có thể thay đổi nhẹ giữa các version.
- An toàn mặc định: không bật fuzzing (-dast) trừ khi người dùng chọn,
  rate-limit mặc định 50 req/s, không tự update template lúc chạy.
"""
import asyncio
import json
import os
import shutil
import tempfile
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

NUCLEI_BIN = "nuclei"
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")


def is_nuclei_available() -> bool:
    return shutil.which(NUCLEI_BIN) is not None


def build_command(targets_file: str, severities: List[str], tags: List[str], fuzz: bool,
                  rate_limit: int, concurrency: int = 10, capture_traffic: bool = False) -> List[str]:
    sev = [s for s in severities if s in VALID_SEVERITIES] or list(VALID_SEVERITIES[:4])
    cmd = [
        NUCLEI_BIN,
        "-l", targets_file,
        "-jsonl",
        "-silent",
        "-nc",                      # no color
        "-duc",                     # disable update check (chạy offline được)
        "-severity", ",".join(sev),
        "-rl", str(max(1, min(int(rate_limit), 500))),
        "-c", str(concurrency),
        "-timeout", "10",
        "-retries", "1",
    ]
    if tags:
        cmd += ["-tags", ",".join(t.strip() for t in tags if t.strip())]
    if capture_traffic:
        cmd.append("-irr")          # include request/response trong JSONL → làm bằng chứng
    if fuzz:
        cmd.append("-dast")         # chạy fuzzing template trên URL có tham số — xâm lấn hơn
    return cmd


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def parse_finding(line: str) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict) or not (d.get("template-id") or d.get("templateID")):
        return None
    info = d.get("info") or {}
    cls = info.get("classification") or {}
    sev = str(info.get("severity") or "info").lower()
    if sev not in VALID_SEVERITIES:
        sev = "info"
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    cve = _first(cls.get("cve-id"))
    cwe = _first(cls.get("cwe-id"))
    cvss = cls.get("cvss-score")
    return {
        "template_id": d.get("template-id") or d.get("templateID"),
        "name": (info.get("name") or d.get("template-id") or "")[:500],
        "severity": sev,
        "matched_at": (d.get("matched-at") or d.get("matched") or d.get("url") or d.get("host") or "")[:2000],
        "host": (d.get("host") or "")[:500],
        "type": d.get("type") or "",
        "matcher_name": d.get("matcher-name") or "",
        "description": (info.get("description") or "")[:4000],
        "remediation": (info.get("remediation") or "")[:4000],
        "reference": [str(r)[:500] for r in refs][:20],
        "tags": [str(t)[:60] for t in tags][:30],
        "cve": str(cve).upper()[:50] if cve else None,
        "cwe": str(cwe).upper()[:50] if cwe else None,
        "cvss_score": str(cvss)[:10] if cvss not in (None, "") else None,
        "extracted": [str(x)[:500] for x in (d.get("extracted-results") or [])][:20],
        "curl_command": (d.get("curl-command") or "")[:4000],
        "request": (d.get("request") or "")[:16000] or None,
        "response": (d.get("response") or "")[:16000] or None,
    }


async def run_nuclei(
    targets: List[str],
    severities: List[str],
    tags: List[str],
    fuzz: bool,
    rate_limit: int,
    timeout: int,
    on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    capture_traffic: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Chạy nuclei → (findings, meta{error, timed_out, stderr_tail})."""
    if not is_nuclei_available():
        return [], {"error": "Tool 'nuclei' chưa được cài. Rebuild Docker image hoặc xem docs/NATIVE_INSTALL.md."}
    if not targets:
        return [], {"error": "Không có URL nào để quét."}

    findings: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {"error": None, "timed_out": False, "stderr_tail": ""}

    with tempfile.TemporaryDirectory(prefix="nuclei_") as tmp:
        tfile = os.path.join(tmp, "targets.txt")
        with open(tfile, "w") as f:
            f.write("\n".join(targets))
        cmd = build_command(tfile, severities, tags, fuzz, rate_limit, capture_traffic=capture_traffic)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                limit=4 * 1024 * 1024,
            )
        except FileNotFoundError:
            return [], {"error": "Tool 'nuclei' không tìm thấy trong PATH."}

        async def _read_stdout():
            assert proc.stdout
            async for raw in proc.stdout:
                item = parse_finding(raw.decode("utf-8", errors="replace").strip())
                if item:
                    findings.append(item)
                    if on_finding:
                        await on_finding(item)

        async def _read_stderr():
            assert proc.stderr
            data = await proc.stderr.read()
            meta["stderr_tail"] = data.decode("utf-8", errors="replace")[-1500:]

        try:
            await asyncio.wait_for(asyncio.gather(_read_stdout(), _read_stderr(), proc.wait()), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            meta["timed_out"] = True
            meta["error"] = f"Nuclei timeout sau {timeout // 60} phút — giữ các finding đã thu được."
        if proc.returncode not in (0, None) and not findings and not meta["error"]:
            meta["error"] = (meta["stderr_tail"].strip()[-500:] or f"nuclei exit code {proc.returncode}")
    return findings, meta
