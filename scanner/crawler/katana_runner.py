"""
Katana crawler wrapper — dùng để build sitemap/endpoint inventory cho 1 domain.

Mục đích: crawl toàn diện một website để liệt kê URL/endpoint/param/form,
làm input cho việc xây dựng baseline WAF (positive security model — chỉ
cho phép các path/param/method đã biết, chặn phần còn lại).

Katana (ProjectDiscovery) được chọn vì:
- Binary Go đơn lẻ, dễ cài cho cả Docker và native (giống Trivy/Gitleaks/Hadolint).
- Hỗ trợ "-jc" (passive JS parsing) để bắt endpoint trong file .js mà không
  cần cài headless Chrome (tránh phình image Docker).
- Hỗ trợ "-fx" (form extraction) để lấy field form — rất hữu ích cho WAF
  baseline (biết param nào hợp lệ trên path nào).
- Output JSONL dễ parse.

Lưu ý: schema JSON của katana có thể thay đổi nhẹ giữa các version, nên
parser dưới đây cố tình "tolerant" — thử nhiều key path khác nhau, không
bao giờ raise nếu thiếu field.
"""
import asyncio
import json
import os
import tempfile
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple


KATANA_BIN = "katana"


def is_katana_available() -> bool:
    import subprocess
    try:
        result = subprocess.run(["which", KATANA_BIN], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def _build_command(
    url: str,
    depth: int,
    js_crawl: bool,
    include_subdomains: bool,
    exclude_patterns: List[str],
    out_file: str,
    max_urls: int,
) -> List[str]:
    cmd = [
        KATANA_BIN,
        "-u", url,
        "-d", str(max(1, depth)),
        "-silent",
        "-jsonl",
        "-fx",                      # form extraction — lấy field form cho WAF baseline
        "-aff",                     # automatic form fill (giúp crawl qua được 1 số form GET)
        "-o", out_file,
        "-c", "10",                 # concurrency
        "-p", "10",                 # parallelism
        "-timeout", "10",
        "-retry", "1",
        # -fs (field-scope): fqdn = chỉ crawl đúng host được khai báo,
        # rdn = root domain name, cho phép crawl cả subdomain.
        # (Trước đây dùng "-cs subdomain/dom" — sai: -cs là regex in-scope,
        # không phải switch chọn domain/subdomain, khiến mọi URL bị lọc hết.)
        "-fs", "rdn" if include_subdomains else "fqdn",
    ]
    if js_crawl:
        cmd.append("-jc")           # passive JS endpoint parsing (không cần headless browser)

    if exclude_patterns:
        # -fr (filter-regex): loại các URL match pattern (vd ảnh, logout...)
        cmd += ["-fr", ",".join(exclude_patterns)]

    # max_urls: katana không có flag đếm cứng ổn định qua các version,
    # nên giới hạn thật sự được áp dụng ở bước parse output (truncate).
    return cmd


async def run_katana(
    url: str,
    depth: int = 3,
    js_crawl: bool = True,
    include_subdomains: bool = False,
    exclude_patterns: Optional[List[str]] = None,
    max_urls: int = 2000,
    timeout: int = 600,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Chạy katana crawl 1 domain, trả về (endpoints, meta).

    endpoints: list dict đã normalize — sẵn sàng lưu vào CrawlEndpoint
    meta: {"raw_lines": int, "truncated": bool, "error": str|None}
    """
    exclude_patterns = exclude_patterns or []

    if not is_katana_available():
        return [], {
            "raw_lines": 0,
            "truncated": False,
            "error": (
                "Tool 'katana' chưa được cài. "
                "Xem docs/NATIVE_INSTALL.md hoặc rebuild Docker image."
            ),
        }

    with tempfile.TemporaryDirectory(prefix="katana_") as tmpdir:
        out_file = os.path.join(tmpdir, "katana_output.jsonl")
        cmd = _build_command(
            url=url,
            depth=depth,
            js_crawl=js_crawl,
            include_subdomains=include_subdomains,
            exclude_patterns=exclude_patterns,
            out_file=out_file,
            max_urls=max_urls,
        )

        error_msg = None
        stderr_text = ""
        returncode = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                returncode = proc.returncode
                stderr_text = stderr.decode("utf-8", errors="replace").strip()
                if returncode not in (0, None) and not os.path.exists(out_file):
                    error_msg = stderr_text[:500] or f"katana exit code {returncode}"
            except asyncio.TimeoutError:
                proc.kill()
                error_msg = f"Crawl timeout sau {timeout}s — kết quả thu được trước đó (nếu có) vẫn được giữ."
        except FileNotFoundError:
            return [], {"raw_lines": 0, "truncated": False, "error": "Tool 'katana' không tìm thấy trong PATH."}
        except Exception as e:
            error_msg = str(e)[:500]

        endpoints, raw_lines = _parse_output(out_file, max_urls)
        truncated = raw_lines > len(endpoints)

        # Katana có thể exit code 0 mà vẫn không tìm thấy URL nào (domain chặn
        # bot/User-Agent, lỗi SSL/DNS, redirect loop, hoặc site cần JS render đầy đủ
        # trong khi katana chỉ parse JS passive — không chạy headless browser thật).
        # Trước đây trường hợp này bị bỏ qua, hiển thị "COMPLETED" với 0 endpoint mà
        # không rõ lý do — giờ luôn cố surface nguyên nhân để debug được.
        if not endpoints and not error_msg:
            if stderr_text:
                error_msg = stderr_text[:500]
            else:
                error_msg = (
                    f"Katana chạy xong (exit code {returncode}) nhưng không tìm thấy URL nào. "
                    "Nguyên nhân có thể: domain chặn crawler/User-Agent, lỗi SSL/DNS, "
                    "redirect không theo được, hoặc site cần JS render đầy đủ (katana chỉ "
                    "parse JS passive, không chạy headless browser). Thử curl thủ công domain "
                    "này từ trong container/máy chạy VulnGuard để kiểm tra kết nối."
                )

        return endpoints, {
            "raw_lines": raw_lines,
            "truncated": truncated,
            "error": error_msg,
        }


def _parse_output(out_file: str, max_urls: int) -> Tuple[List[Dict[str, Any]], int]:
    if not os.path.exists(out_file):
        return [], 0

    endpoints: List[Dict[str, Any]] = []
    seen = set()
    raw_lines = 0

    with open(out_file, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw_lines += 1
            try:
                obj = json.loads(line)
            except Exception:
                continue

            parsed = _normalize_record(obj)
            if not parsed:
                continue

            dedup_key = (parsed["method"], parsed["url"])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            endpoints.append(parsed)
            if len(endpoints) >= max_urls:
                break

    return endpoints, raw_lines


def _normalize_record(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tolerant parser — chấp nhận vài biến thể schema JSON của katana."""
    request = obj.get("request") if isinstance(obj.get("request"), dict) else {}
    response = obj.get("response") if isinstance(obj.get("response"), dict) else {}

    url = (
        obj.get("endpoint")
        or request.get("endpoint")
        or obj.get("url")
        or request.get("url")
    )
    if not url or not isinstance(url, str):
        return None

    method = (request.get("method") or obj.get("method") or "GET").upper()

    status_code = response.get("status_code") or obj.get("status_code")
    try:
        status_code = int(status_code) if status_code is not None else None
    except (ValueError, TypeError):
        status_code = None

    headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
    content_type = None
    for k, v in headers.items():
        if str(k).lower() in ("content-type", "content_type"):
            content_type = v
            break

    source_tag = obj.get("tag") or request.get("tag") or obj.get("attribute")

    try:
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path or "/"
        query_params = sorted(set(urllib.parse.parse_qs(parsed_url.query).keys()))
    except Exception:
        path = url
        query_params = []

    forms_raw = obj.get("forms") or response.get("forms") or []
    forms = []
    body_params = set()
    if isinstance(forms_raw, list):
        for form in forms_raw:
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") or form.get("inputs") or []
            field_names = []
            for fld in fields:
                if isinstance(fld, dict):
                    fname = fld.get("name") or fld.get("id")
                    if fname:
                        field_names.append(fname)
                        body_params.add(fname)
                elif isinstance(fld, str):
                    field_names.append(fld)
                    body_params.add(fld)
            forms.append({
                "method": (form.get("method") or "GET").upper(),
                "action": form.get("action") or path,
                "fields": field_names,
            })

    return {
        "url": url,
        "path": path,
        "method": method,
        "status_code": status_code,
        "content_type": str(content_type)[:200] if content_type else None,
        "source_tag": str(source_tag)[:50] if source_tag else None,
        "query_params": query_params,
        "body_params": sorted(body_params),
        "forms": forms,
    }
