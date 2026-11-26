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
                  rate_limit: int, concurrency: int = 10, capture_traffic: bool = False,
                  exclude_tags: List[str] = None, safe_net: bool = False,
                  proxy: Optional[str] = None) -> List[str]:
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
    if exclude_tags:
        cmd += ["-etags", ",".join(t.strip() for t in exclude_tags if t.strip())]  # P0.9
    if safe_net:
        # Pentest Agent: không theo redirect của template ra ngoài scope (-dr) và không gửi callback
        # OAST tới server interactsh công cộng của bên thứ ba (-ni)
        cmd += ["-dr", "-ni"]
    if proxy:
        # Pentest Agent: mọi request HTTP đi qua proxy ghim IP (không tự phân giải DNS → chống rebinding);
        # chỉ chạy template http (network/tcp/dns… bỏ qua proxy nên bị loại)
        cmd += ["-proxy", proxy, "-pt", "http"]
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
    exclude_tags: List[str] = None,
    safe_net: bool = False,
    proxy: Optional[str] = None,
    backend: Any = None,
    step_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Chạy nuclei → (findings, meta{error, timed_out, stderr_tail}).
    backend (P2-4): ExecBackend `sandbox` → chạy trong sandbox qua runner (argv y hệt, `-u` thay cho `-l <file host>`)."""
    if backend is not None and getattr(backend, "name", "") == "sandbox":
        return await _run_nuclei_sandbox(backend, step_id, targets, severities, tags, fuzz, rate_limit, timeout,
                                         on_finding, capture_traffic, exclude_tags, safe_net)
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
        cmd = build_command(tfile, severities, tags, fuzz, rate_limit,
                            capture_traffic=capture_traffic, exclude_tags=exclude_tags, safe_net=safe_net, proxy=proxy)
        try:
            # Đi qua registry của Pentest Agent: nhóm process riêng + kill switch giết được (F1/F3)
            from scanner.pentest.procs import REGISTRY, RunStopped, current_run_id, spawn
            rid = current_run_id.get()
            proc = await spawn(*cmd, run_id=rid, stdout=asyncio.subprocess.PIPE,
                               stderr=asyncio.subprocess.PIPE, limit=4 * 1024 * 1024)
        except FileNotFoundError:
            return [], {"error": "Tool 'nuclei' không tìm thấy trong PATH."}
        except RunStopped as e:
            return [], {"error": str(e)}

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
            await REGISTRY.kill_all_proc(proc)
            meta["timed_out"] = True
            meta["error"] = f"Nuclei timeout sau {timeout // 60} phút — giữ các finding đã thu được."
        except asyncio.CancelledError:
            await REGISTRY.kill_all_proc(proc)   # STOP/watchdog huỷ task → không để nuclei mồ côi
            raise
        finally:
            REGISTRY.unregister(rid, proc)
        if proc.returncode not in (0, None) and not findings and not meta["error"]:
            meta["error"] = (meta["stderr_tail"].strip()[-500:] or f"nuclei exit code {proc.returncode}")
    return findings, meta


async def _run_nuclei_sandbox(backend, step_id, targets, severities, tags, fuzz, rate_limit, timeout, on_finding,
                              capture_traffic, exclude_tags, safe_net):
    if not targets:
        return [], {"error": "Không có URL nào để quét."}
    cmd = build_command("-", severities, tags, fuzz, rate_limit, capture_traffic=capture_traffic,
                        exclude_tags=exclude_tags, safe_net=safe_net, proxy=None)
    i = cmd.index("-l")
    cmd[i:i + 2] = [x for t in targets for x in ("-u", t)]    # file target của host không tới được sandbox
    from scanner.pentest.procs import current_run_id
    res = await backend.run_argv(cmd, timeout, run_id=current_run_id.get(), step_id=step_id, max_output=1)
    findings: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {"error": None, "timed_out": bool(res.get("timed_out")), "stderr_tail": (res.get("stderr") or "")[-1500:]}
    for line in (res.get("stdout") or "").splitlines():
        item = parse_finding(line.strip())
        if item:
            findings.append(item)
            if on_finding:
                await on_finding(item)
    if res.get("timed_out"):
        meta["error"] = f"Nuclei timeout sau {timeout // 60} phút — giữ các finding đã thu được."
    elif res.get("error"):
        meta["error"] = str(res["error"])[:500]
    elif res.get("returncode") not in (0, None) and not findings:
        meta["error"] = meta["stderr_tail"].strip()[-500:] or f"nuclei exit code {res.get('returncode')}"
    return findings, meta
