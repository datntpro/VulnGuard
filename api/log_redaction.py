"""[AI PR-2] Bộ lọc log che key AI + chặn debug SDK ở production.

`install()` bọc LogRecordFactory: MỌI record (mọi logger/handler, kể cả uvicorn) được che message + traceback
NGAY khi tạo, nên key lỡ lọt vào `logger.exception(request)` hay SDK debug-log không ra file/console.
Mẫu: sk-ant-, sk-, sk-or-, ABSK, ksk_, AIza, ghp_/github_pat_, `Bearer …`, `x-api-key: …`, query ?key=…
"""
import logging
import os
import re
import traceback

_installed = False
_BEARER = re.compile(r"(?i)\b(bearer|x-api-key:?|api-key:?|authorization:?)\s+[A-Za-z0-9._~+/=\-]{8,}")
_QS = re.compile(r"(?i)([?&](?:key|api[_-]?key|token|access_token|sig|signature)=)[^&\s'\"]+")
# tên "giống khoá" + dấu : / = (cho phép dict-repr: 'x-api-key': 'abc') → che GIÁ TRỊ
_KEYISH = re.compile(
    r"""(?i)((?<![A-Za-z0-9])(?:x-api-key|api[_-]?key|authorization|access[_-]?key|secret[_-]?key|client[_-]?secret|secret|token|password|passwd)"""
    r"""['"]?\s*[:=]\s*['"]?)([^'"\s,}&)]{6,})""")
# token dài ≥40 ký tự: chỉ QUÉT bằng regex tuyến tính, kiểm tra thường+HOA+số trong callback (tránh lookahead bậc hai)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-]{40,}")
MAX_SCAN = 32 * 1024     # trần ký tự quét mỗi record (regex khoá cũ có thể chậm trên chuỗi dài) — phần dư bị cắt
_NO_DEBUG_ENV = ("ANTHROPIC_LOG", "OPENAI_LOG")


def _entropy_cb(m) -> str:
    t = m.group(0)
    return "[REDACTED-KEY]" if (any(c.isdigit() for c in t) and any(c.islower() for c in t)
                                 and any(c.isupper() for c in t)) else t


def mask(text: str) -> str:
    """Che secret trong một chuỗi log (giữ URL/PII — chỉ che khoá)."""
    if not text or not isinstance(text, str):
        return text
    from scanner import cloud_ai
    if len(text) > MAX_SCAN:   # che phần đầu rồi cắt: dòng log khổng lồ không được làm nghẽn logging
        return mask(text[:MAX_SCAN]) + f"…[truncated {len(text) - MAX_SCAN} chars]"
    for pat in cloud_ai._SECRET_PATTERNS:
        text = pat.sub("[REDACTED-KEY]", text)
    text = _BEARER.sub(lambda m: m.group(1) + " [REDACTED]", text)
    text = _KEYISH.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = _LONG_TOKEN.sub(_entropy_cb, text)
    return _QS.sub(lambda m: m.group(1) + "[REDACTED]", text)


class SecretMaskFilter(logging.Filter):
    """Dùng được như filter của handler/logger (cùng logic với factory)."""
    def filter(self, record: logging.LogRecord) -> bool:
        _scrub(record)
        return True


def _scrub(record: logging.LogRecord) -> None:
    try:
        msg = record.getMessage()
    except Exception:
        msg = str(record.msg)
    record.msg, record.args = mask(msg), None
    if record.exc_info and not getattr(record, "_vg_scrubbed", False):
        et, ev, tb = record.exc_info
        record.exc_text = mask("".join(traceback.format_exception(et, ev, tb)).rstrip("\n"))
    elif record.exc_text:
        record.exc_text = mask(record.exc_text)
    if record.stack_info:
        record.stack_info = mask(record.stack_info)
    record._vg_scrubbed = True


def install() -> None:
    global _installed
    if _installed:
        return
    base = logging.getLogRecordFactory()

    def factory(*a, **kw):
        rec = base(*a, **kw)
        _scrub(rec)
        return rec

    logging.setLogRecordFactory(factory)
    _installed = True


def check_sdk_debug_env(app_env: str) -> None:
    """Production: từ chối khởi động nếu SDK ở chế độ debug (header Authorization có thể vào log)."""
    if (app_env or "").lower() != "production":
        return
    bad = [k for k in _NO_DEBUG_ENV if (os.environ.get(k) or "").strip().lower() == "debug"]
    if bad:
        raise RuntimeError(f"Từ chối khởi động ở production: {', '.join(bad)}=debug có thể ghi key vào log. "
                           "Bỏ biến này.")
