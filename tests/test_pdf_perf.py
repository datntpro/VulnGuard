"""2 000 findings: < 10 s wall, worker peak RSS < 800 MB (plan §10). Nightly + PDF PRs: pytest -m slow."""
import threading
import time

import psutil
import pytest

from scanner.pdf import adapters, engine
from tests._pdf_fixtures import NOW, make_scan

pytestmark = pytest.mark.slow


def test_2000_findings_time_and_memory():
    p, s, g, c = make_scan(2000)
    doc = adapters.scan_doc(p, s, g, c, now=NOW)
    peak = [0]
    stop = threading.Event()

    def watch():
        me = psutil.Process()
        while not stop.is_set():
            kids = me.children(recursive=True)
            try:
                peak[0] = max(peak[0], sum(k.memory_info().rss for k in kids))
            except psutil.Error:
                pass
            time.sleep(0.05)

    t = threading.Thread(target=watch, daemon=True)
    t.start()
    t0 = time.time()
    pdf = engine.render("scan", doc, generated_at=0)
    dt = time.time() - t0
    stop.set()
    t.join()
    assert pdf.startswith(b"%PDF-")
    assert dt < 10, dt
    assert peak[0] < 800 * 1024 * 1024, peak[0] / 1e6
