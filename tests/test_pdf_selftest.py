"""PR-4: self-test used by Docker build, setup.py --check and run.sh."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.pdf import selftest

ROOT = Path(__file__).resolve().parent.parent


def test_selftest_passes_in_process():
    res = selftest.run_all()
    assert res and all(err is None for _, err in res), res


def test_selftest_cli_ok():
    p = subprocess.run([sys.executable, "-m", "scanner.pdf.selftest", "--quiet"],
                       cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.strip().startswith("PDF engine: typst ") and p.stdout.strip().endswith("OK")


def test_selftest_reports_why_when_wheel_missing(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "typst", None)  # import typst -> ImportError
    assert selftest.main([]) == 1
    cap = capsys.readouterr()
    assert "typst wheel not importable" in cap.out
    assert "FAILED" in cap.err and "requirements.txt" in cap.err


def test_selftest_detects_bad_font():
    from unittest import mock

    pdf = selftest.check_render()
    selftest.check_fonts(pdf)  # baseline ok
    with mock.patch.object(selftest, "ALLOWED_FONT", re.compile(r"^nothing$")):
        with pytest.raises(selftest.SelfTestError, match="unexpected font"):
            selftest.check_fonts(pdf)


def test_dockerfile_runs_selftest_after_source_copy():
    df = (ROOT / "api" / "Dockerfile").read_text()
    i_run = df.index("scanner.pdf.selftest")
    assert i_run > df.index("COPY scanner/ ./scanner/")
    assert "--require-hashes -r requirements.txt" in df


# ---- F1: the network check must prove the network is unreachable, not just "some error" ----
import socket
import threading

from scanner.pdf import engine
from scanner.pdf.errors import PdfCompileError, PdfEngineError


class _TunnelProxy:
    """Reachable 'network': accepts CONNECT, says 200, then closes -> the package download is
    *attempted and reaches a live peer* (unlike the dead proxy, which refuses the connection)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.hits = 0
        threading.Thread(target=self._run, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.sock.getsockname()[1]

    def _run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.hits += 1
            try:
                c.recv(4096)
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except OSError:
                pass
            c.close()


def test_network_check_passes_with_dead_proxy():
    selftest.check_no_network()


def test_network_check_fails_when_peer_reachable():
    px = _TunnelProxy()
    try:
        with pytest.raises(selftest.SelfTestError):
            selftest.check_no_network(proxy=px.url)
        assert px.hits >= 1  # the download really reached a live peer
    finally:
        px.sock.close()


def test_network_check_fails_on_success_or_unrelated_error(monkeypatch):
    monkeypatch.setattr(engine, "run_worker", lambda *a, **k: b"%PDF-")
    with pytest.raises(selftest.SelfTestError, match="NOT active"):
        selftest.check_no_network()
    for exc in (PdfEngineError("worker boom"), PdfCompileError("failed to decompress package (x)"),
                PdfCompileError("some other typst error")):
        def boom(*a, _e=exc, **k):
            raise _e
        monkeypatch.setattr(engine, "run_worker", boom)
        with pytest.raises(selftest.SelfTestError):
            selftest.check_no_network()


def test_reports_network_check_failed(monkeypatch, capsys):
    monkeypatch.setattr(selftest, "check_no_network", lambda: (_ for _ in ()).throw(selftest.SelfTestError("reachable")))
    assert selftest.main([]) == 1
    assert "FAIL @preview import blocked" in capsys.readouterr().out


def test_render_path_always_uses_dead_proxy():
    import inspect

    assert inspect.signature(engine.run_worker).parameters["proxy"].default == engine.DEAD_PROXY
    assert engine.DEAD_PROXY.startswith("http://127.0.0.1:")
    src = inspect.getsource(engine.render)
    assert "proxy" not in src  # render() cannot override it
