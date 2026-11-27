"""Network kill-switch (plan §5 F4-F6): packages forbidden/blocked, dead proxy in the worker,
and a normal render makes zero outbound connection attempts."""
import socket
import threading

import pytest

from scanner.pdf import engine
from scanner.pdf.engine import DEAD_PROXY, _worker_env, run_worker
from scanner.pdf.errors import PdfCompileError
from scanner.pdf.root import build_workspace
from tests._pdf_helpers import compile_src


class Listener:
    def __init__(self):
        self.s = socket.socket()
        self.s.bind(("127.0.0.1", 0))
        self.s.listen(8)
        self.s.settimeout(0.2)
        self.hits: list[bytes] = []
        self._stop = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.s.getsockname()[1]

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self.s.accept()
            except (socket.timeout, OSError):
                continue
            try:
                c.settimeout(1)
                self.hits.append(c.recv(512))
                c.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        self.t.join(1)
        self.s.close()


@pytest.fixture
def listener():
    l = Listener()
    yield l
    l.close()


def test_worker_env_has_dead_proxy_and_no_inherited_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    env = _worker_env(tmp_path)
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        assert env[k] == DEAD_PROXY
    assert env["NO_PROXY"] == "" and env["no_proxy"] == ""
    assert "AWS_SECRET_ACCESS_KEY" not in env and "ANTHROPIC_API_KEY" not in env
    assert env["HOME"] == str(tmp_path)


def test_preview_import_fails_with_dead_proxy():
    with pytest.raises(PdfCompileError) as ei:
        compile_src('#import "@preview/tablex:0.0.9": tablex\nok')
    assert "package" in str(ei.value).lower()


def test_local_package_not_found():
    with pytest.raises(PdfCompileError):
        compile_src('#import "@local/evil:0.1.0": *\nok')


def test_positive_control_env_is_honoured(listener):
    """With a listening proxy the package fetch shows up as CONNECT -> proves the env knob
    is what blocks it (and that a counted listener would catch a real attempt)."""
    with pytest.raises(PdfCompileError):
        compile_src('#import "@preview/tablex:0.0.9": tablex\nok', proxy=listener.url, timeout_s=20)
    assert any(h.startswith(b"CONNECT") for h in listener.hits)


def test_normal_render_makes_zero_connections(listener, monkeypatch):
    real = engine.run_worker

    def via_listener(ws, inputs, **kw):
        kw["proxy"] = listener.url
        return real(ws, inputs, **kw)

    monkeypatch.setattr(engine, "run_worker", via_listener)
    pdf = engine.render("scan", {"title": "t", "findings": [{"title": "a", "description": "b"}]}, generated_at=0)
    assert pdf.startswith(b"%PDF-")
    assert listener.hits == []


def test_package_dirs_are_empty_and_outside_root():
    with build_workspace() as ws:
        assert ws.packages.parent == ws.base and ws.root not in ws.packages.parents
        assert ws.pkg_cache.parent == ws.base
