"""Resource limits: timeout, RSS cap, output cap, input caps, concurrency (plan §4)."""
import sys
import threading
import time

import psutil
import pytest

from scanner.pdf import engine
from scanner.pdf.errors import (
    PdfEngineError,
    PdfInputTooLarge,
    PdfInvalidInput,
    PdfOutputTooLarge,
    PdfTimeout,
    PdfWorkerKilled,
)
from tests._pdf_helpers import compile_src

HOG = "#for i in range(3000000) [x ]"


def _no_orphans():
    me = psutil.Process()
    deadline = time.time() + 3
    while time.time() < deadline:
        if not me.children(recursive=True):
            return True
        time.sleep(0.1)
    return False


def test_timeout_kills_worker_promptly_without_orphans():
    t = time.monotonic()
    with pytest.raises(PdfTimeout):
        compile_src(HOG, timeout_s=1.5)
    assert time.monotonic() - t < 1.5 + 2.0
    assert _no_orphans()


def test_rss_cap_kills_worker():
    with pytest.raises(PdfWorkerKilled):
        compile_src(HOG, max_rss=120 * 1024 * 1024, timeout_s=30)
    assert _no_orphans()


def test_output_cap():
    with pytest.raises(PdfOutputTooLarge):
        compile_src("hello", max_pdf=500)
    assert _no_orphans()


def test_oversized_data_rejected_before_worker(monkeypatch):
    monkeypatch.setattr(engine, "MAX_DATA_BYTES", 1000)
    monkeypatch.setattr(engine, "run_worker", lambda *a, **k: pytest.fail("worker must not start"))
    with pytest.raises(PdfInputTooLarge):
        engine.render("scan", {"title": "x", "findings": [{"description": "y" * 100}] * 50})


def test_unknown_kind_and_bad_types_rejected(monkeypatch):
    monkeypatch.setattr(engine, "run_worker", lambda *a, **k: pytest.fail("worker must not start"))
    with pytest.raises(PdfInvalidInput):
        engine.render("evil", {})  # type: ignore[arg-type]
    with pytest.raises(PdfInvalidInput):
        engine.render("scan", {"x": object()})


@pytest.mark.parametrize(
    "svg",
    [
        '<svg><image href="http://x/y.png"/></svg>',
        '<svg><use href="/etc/hosts"/></svg>',
        '<svg><style>@import url(http://x)</style></svg>',
        '<svg xmlns:xlink="http://www.w3.org/1999/xlink"/>',
        "<!DOCTYPE svg><svg/>",
        "not svg",
    ],
)
def test_chart_svg_with_references_rejected(svg):
    with pytest.raises(PdfInvalidInput):
        engine.validate_chart_svg(svg)


def test_chart_svg_numeric_ok():
    engine.validate_chart_svg('<svg viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" stroke-dasharray="3 7"/></svg>')


def test_concurrency_semaphore_default_and_blocking(monkeypatch):
    assert engine.CONCURRENCY == 2
    sem = threading.BoundedSemaphore(1)
    sem.acquire()
    monkeypatch.setattr(engine, "_SEM", sem)
    with pytest.raises(PdfTimeout):
        engine.render("scan", {"title": "x"}, timeout_s=0.3)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="RLIMIT_AS enforceable on Linux only")
def test_rlimit_as_enforced_on_linux():
    with pytest.raises(PdfEngineError):
        compile_src("hi", max_as=64 * 1024 * 1024, max_rss=0)


def test_page_cap(monkeypatch):
    pdf = engine.render("scan", {"title": "x"}, generated_at=0)
    with pytest.raises(PdfOutputTooLarge):
        engine.check_pdf(pdf, max_pages=0)
