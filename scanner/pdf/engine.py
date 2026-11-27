"""Hardened Typst PDF engine.

Only entry point for callers: :func:`render`. There is deliberately no "render arbitrary
source" API: templates are our own files; report data travels as JSON in ``sys.inputs``.
"""
from __future__ import annotations

import io
import json
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Literal, Mapping, Optional

from .errors import (
    PdfCompileError,
    PdfEngineError,
    PdfInputTooLarge,
    PdfBusy,
    PdfInvalidInput,
    PdfOutputTooLarge,
    PdfTimeout,
    PdfWorkerKilled,
)
from .root import Workspace, build_workspace
from .sanitize import sanitize

Kind = Literal["scan", "pentest", "webscan", "docreview"]
KINDS = ("scan", "pentest", "webscan", "docreview")

WORKER_PATH = Path(__file__).resolve().parent / "worker.py"
ENTRY = "report.typ"

MAX_DATA_BYTES = 8 * 1024 * 1024  # adversarial no-space payloads near 30 MB reached 1.5 GB RSS (PR-1 verify F4)
MAX_CHART_BYTES = 256 * 1024
MAX_PDF_BYTES = int(os.environ.get("VG_PDF_MAX_BYTES", 100 * 1024 * 1024))
MAX_PAGES = 2000
MAX_RSS_BYTES = int(float(os.environ.get("VG_PDF_MAX_RSS_MB", 1536)) * 1024 * 1024)
MAX_AS_BYTES = int(float(os.environ.get("VG_PDF_MAX_AS_MB", 1536)) * 1024 * 1024)
DEFAULT_TIMEOUT_S = 60.0
CONCURRENCY = max(1, int(os.environ.get("VG_PDF_CONCURRENCY", 2)))
_SEM = threading.BoundedSemaphore(CONCURRENCY)
BUSY_WAIT_S = float(os.environ.get("VG_PDF_BUSY_WAIT_S", 1.0))

# adapter-level input caps (plan §4)
MAX_FINDINGS = 5000
MAX_TITLE = 300
MAX_TEXT = 8192
MAX_CODE_LINES = 200
_CODE_KEYS = frozenset({"code", "evidence", "snippet", "request", "response"})

# Dead proxy: Typst's only network feature is package download (probe F4/F5).
DEAD_PROXY = "http://127.0.0.1:9"

# Chart SVG is generated from integers only; refuse anything that could reference a resource.
_SVG_FORBIDDEN = re.compile(
    r"(?i)<\s*(image|use|script|foreignObject|style|a)\b|href|xlink|url\s*\(|@import|<!\s*(entity|doctype)|data:|javascript:|https?:|file:"
)


def _worker_env(home: Path, proxy: str = DEAD_PROXY) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "HTTPS_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "ALL_PROXY": proxy,
        "https_proxy": proxy,
        "http_proxy": proxy,
        "all_proxy": proxy,
        "NO_PROXY": "",
        "no_proxy": "",
    }
    for k in ("SYSTEMROOT", "SYSTEMDRIVE"):  # Windows needs these to start python
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            import psutil

            for c in psutil.Process(proc.pid).children(recursive=True):
                c.kill()
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _rss(proc: subprocess.Popen) -> int:
    try:
        import psutil

        p = psutil.Process(proc.pid)
        total = p.memory_info().rss
        for c in p.children(recursive=True):
            try:
                total += c.memory_info().rss
            except psutil.Error:
                pass
        return total
    except Exception:  # noqa: BLE001 - process gone / psutil missing
        return 0


def run_worker(
    ws: Workspace,
    sys_inputs: Mapping[str, str],
    *,
    entry: str = ENTRY,
    timestamp: Optional[int] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_rss: int = MAX_RSS_BYTES,
    max_as: int = MAX_AS_BYTES,
    max_pdf: int = MAX_PDF_BYTES,
    proxy: str = DEAD_PROXY,
    poll_s: float = 0.02,
) -> bytes:
    """Compile ``entry`` from ``ws.root`` in the sandboxed worker. Returns PDF bytes."""
    if max_rss and not sys.platform.startswith("linux"):
        # RLIMIT_AS is not enforceable here: the psutil RSS poll is the only memory cap, so
        # refuse to run without it (fail closed).
        try:
            import psutil  # noqa: F401
        except ImportError as e:
            raise PdfEngineError("memory watchdog unavailable (psutil missing); refusing to render") from e
    job = json.dumps(
        {
            "entry": entry,
            "root": str(ws.root),
            "fonts_dir": str(ws.root / "fonts"),
            "packages": str(ws.packages),
            "pkg_cache": str(ws.pkg_cache),
            "inputs": dict(sys_inputs),
            "timestamp": timestamp,
        },
        ensure_ascii=False,
    ).encode("utf-8")
    limits = json.dumps(
        {
            "as_bytes": max_as,
            "cpu_s": int(timeout_s) + 5,
            "nofile": 64,
            "fsize": 0,
        }
    )
    kwargs: dict[str, Any] = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:  # pragma: no cover
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    proc = subprocess.Popen(
        [sys.executable, "-I", str(WORKER_PATH), limits],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(ws.root),
        env=_worker_env(ws.home, proxy),
        close_fds=True,
        **kwargs,
    )
    out = io.BytesIO()
    err = io.BytesIO()
    over = threading.Event()

    def pump_out() -> None:
        assert proc.stdout
        while True:
            chunk = proc.stdout.read(1 << 16)
            if not chunk:
                return
            if out.tell() + len(chunk) > max_pdf:
                over.set()
                _kill_tree(proc)
                return
            out.write(chunk)

    def pump_err() -> None:
        assert proc.stderr
        while True:
            chunk = proc.stderr.read(4096)
            if not chunk:
                return
            if err.tell() < 8192:
                err.write(chunk[: 8192 - err.tell()])

    def feed() -> None:
        assert proc.stdin
        try:
            proc.stdin.write(struct.pack(">I", len(job)) + job)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    threads = [threading.Thread(target=f, daemon=True) for f in (pump_out, pump_err, feed)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout_s
    reason: Optional[str] = None
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline:
                reason = "timeout"
            elif max_rss and _rss(proc) > max_rss:
                reason = "memory"
            elif over.is_set():
                reason = "output"
            if reason:
                _kill_tree(proc)
                break
            time.sleep(poll_s)
        proc.wait(timeout=5)
    finally:
        _kill_tree(proc) if proc.poll() is None else None
        if os.name == "posix":  # reap any stragglers in the worker's session
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        for t in threads:
            t.join(timeout=5)
    if over.is_set() or reason == "output":
        raise PdfOutputTooLarge("pdf output exceeds limit")
    if reason == "timeout":
        raise PdfTimeout("pdf render timed out")
    if reason == "memory":
        raise PdfWorkerKilled("pdf worker exceeded memory limit")
    rc = proc.returncode
    detail = _scrub_paths(err.getvalue().decode("utf-8", "replace").strip(), ws)[:500]
    if rc == 0:
        data = out.getvalue()
        if not data.startswith(b"%PDF-"):
            raise PdfEngineError("worker returned non-PDF output")
        return data
    if rc == 2:
        raise PdfCompileError(detail or "typst compile error")
    if rc is not None and rc < 0:  # killed by signal (RLIMIT_CPU/AS abort, SIGXFSZ ...)
        raise PdfWorkerKilled(f"pdf worker died on signal {-rc}")
    raise PdfEngineError(f"pdf worker failed (exit {rc}): {detail}")


def _scrub_paths(msg: str, ws: Workspace) -> str:
    """Never leak the temp workspace (or any absolute path) in error text."""
    paths = {str(ws.base), str(ws.base.resolve()), str(ws.root), str(ws.root.resolve())}
    for p in sorted(paths, key=len, reverse=True):  # longest first: /private/var/... before /var/...
        msg = msg.replace(p, "<work>")
    msg = msg.replace("/private<work>", "<work>")
    msg = re.sub(r"vg-pdf-[A-Za-z0-9_]+", "<work>", msg)
    return re.sub(r"(?<![\w<])/(?:[\w.@+-]+/)+", "<path>/", msg)


def check_pdf(data: bytes, *, max_pages: int = MAX_PAGES) -> int:
    from pypdf import PdfReader

    try:
        n = len(PdfReader(io.BytesIO(data)).pages)
    except Exception as e:  # noqa: BLE001
        raise PdfEngineError("worker returned an unreadable PDF") from e
    if n > max_pages:
        raise PdfOutputTooLarge(f"pdf has {n} pages (max {max_pages})")
    return n


def validate_chart_svg(svg: str) -> str:
    if len(svg.encode("utf-8")) > MAX_CHART_BYTES:
        raise PdfInputTooLarge("chart svg too large")
    s = svg.lstrip()
    if not s.startswith("<svg") or _SVG_FORBIDDEN.search(s):
        raise PdfInvalidInput("chart svg rejected")
    return svg


def apply_caps(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Cap findings count and per-field sizes before serialisation (plan §4, D5)."""
    out = dict(doc)
    fs = out.get("findings")
    if isinstance(fs, list):
        if len(fs) > MAX_FINDINGS:
            out["findings_truncated_from"] = len(fs)
            fs = fs[:MAX_FINDINGS]
        capped = []
        for f in fs:
            if not isinstance(f, Mapping):
                capped.append(f)
                continue
            g = dict(f)
            for k, v in g.items():
                if not isinstance(v, str):
                    continue
                if k == "title":
                    g[k] = v[:MAX_TITLE]
                elif k in _CODE_KEYS:
                    lines = v.split("\n")
                    if len(lines) > MAX_CODE_LINES:
                        lines = lines[:MAX_CODE_LINES] + ["…"]
                    g[k] = "\n".join(lines)[:MAX_TEXT]
                else:
                    g[k] = v[:MAX_TEXT]
            capped.append(g)
        out["findings"] = capped
    return out


def render(
    kind: Kind,
    doc: Mapping[str, Any],
    *,
    chart_svg: Optional[str] = None,
    generated_at: Optional[int] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> bytes:
    """Render ``doc`` (a JSON-able mapping) with the ``kind`` report template to PDF bytes.

    All strings in ``doc`` are sanitised and passed to Typst as a single ``sys.inputs`` JSON
    value; nothing is ever interpolated into Typst source.
    """
    if kind not in KINDS:
        raise PdfInvalidInput("unknown report kind")
    try:
        clean = sanitize(apply_caps(doc))
    except (TypeError, ValueError) as e:
        raise PdfInvalidInput(str(e)) from e
    clean["kind"] = kind
    data = json.dumps(clean, ensure_ascii=False, separators=(",", ":"))
    if len(data.encode("utf-8")) > MAX_DATA_BYTES:
        raise PdfInputTooLarge("report data exceeds size cap")
    inputs = {"data": data}
    if chart_svg is not None:
        inputs["chart_svg"] = validate_chart_svg(chart_svg)
    if not _SEM.acquire(timeout=BUSY_WAIT_S):
        raise PdfBusy("pdf renderer busy; retry shortly")
    try:
        with build_workspace() as ws:
            pdf = run_worker(ws, inputs, timestamp=generated_at, timeout_s=timeout_s)
    finally:
        _SEM.release()
    check_pdf(pdf)
    return pdf
