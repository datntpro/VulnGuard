"""P2-1: vg_exec shim + vg_http + Dockerfile hardening (thuần python, không cần Docker)."""
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path

import pytest

DIR = Path(__file__).resolve().parent.parent / "docker" / "pentest-runner"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vg_exec = _load("vg_exec")


# ── allowlist ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("argv", [
    ["nmap", "-sV", "10.0.0.1"], ["ffuf", "-u", "http://x/FUZZ"], ["nuclei", "-u", "http://x"],
    ["sqlmap", "-u", "http://x"], ["katana", "-u", "http://x"], ["httpx", "-u", "http://x"],
    ["python3", "-m", "vg_http"], ["python3", "-m", "vg_browser", "--x"],
])
def test_allowed_argv(argv):
    assert vg_exec.validate_argv(argv) == argv


@pytest.mark.parametrize("argv", [
    [], "nmap", ["sh", "-c", "id"], ["/usr/bin/nmap", "x"], ["./nmap"], ["NMAP"], ["nmap "], ["curl", "http://x"],
    ["python3"], ["python3", "-c", "print(1)"], ["python3", "-m", "os"], ["python3", "x.py"],
    ["python3", "-m", "vg_http_evil"], ["nmap", 5], ["nmap", None],
])
def test_refused_argv(argv):
    with pytest.raises(vg_exec.ExecRefused):
        vg_exec.validate_argv(argv)


def test_nul_refused():
    with pytest.raises(vg_exec.ExecRefused, match="NUL"):
        vg_exec.validate_argv(["nmap", "a\x00b"])


def test_unknown_tool_and_mismatch():
    with pytest.raises(vg_exec.ExecRefused):
        vg_exec.validate_argv(["rm", "-rf", "/"], tool="rm")
    with pytest.raises(vg_exec.ExecRefused, match="does not match"):
        vg_exec.validate_argv(["nmap", "x"], tool="ffuf")
    assert vg_exec.validate_argv(["python3", "-m", "vg_http"], tool="python3 -m vg_http")


# ── run_step ───────────────────────────────────────────────────────────────
@pytest.fixture
def fake_tools(monkeypatch, tmp_path):
    """Thay allowlist/SEARCH_PATH bằng tool giả trong tmp (không chạy tool thật)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in {
        "nmap": "#!/bin/sh\necho out-$1\necho err >&2\nexit 3\n",
        "ffuf": "#!/bin/sh\n/bin/sleep 30\n",
    }.items():
        p = bindir / name
        p.write_text(body)
        p.chmod(0o755)
    monkeypatch.setattr(vg_exec, "SEARCH_PATH", str(bindir))
    monkeypatch.setattr(vg_exec, "KILL_GRACE_S", 0.5)
    return tmp_path / "work"


def test_run_step_writes_files(fake_tools):
    res = vg_exec.run_step(["nmap", "hello"], tool="nmap", step="s1", timeout_s=10, work_root=str(fake_tools))
    assert res["returncode"] == 3 and res["timed_out"] is False
    assert Path(res["stdout_path"]).read_text() == "out-hello\n"
    assert Path(res["stderr_path"]).read_text() == "err\n"
    assert json.loads((fake_tools / "s1" / "result.json").read_text()) == res


def test_run_step_timeout_kills_group(fake_tools):
    t0 = time.monotonic()
    res = vg_exec.run_step(["ffuf", "x"], step="s2", timeout_s=0.5, work_root=str(fake_tools))
    assert res["timed_out"] is True and res["returncode"] != 0
    assert time.monotonic() - t0 < 10


@pytest.mark.parametrize("step", ["../x", "a/b", "", ".hidden", "x" * 65, "a b", "..", "/abs"])
def test_step_id_traversal_refused(fake_tools, step):
    with pytest.raises(vg_exec.ExecRefused):
        vg_exec.run_step(["nmap", "x"], step=step, work_root=str(fake_tools))


def test_missing_binary_refused(fake_tools):
    with pytest.raises(vg_exec.ExecRefused, match="not found"):
        vg_exec.run_step(["katana", "x"], step="s3", work_root=str(fake_tools))


def test_env_is_scrubbed(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_TOKEN", "x")
    monkeypatch.setenv("HTTP_PROXY", "http://gw:8080")
    env = vg_exec.clean_env(str(tmp_path))
    assert "SECRET_TOKEN" not in env and env["HTTP_PROXY"] == "http://gw:8080"
    assert env["PATH"] == vg_exec.SEARCH_PATH  # không kế thừa PATH của caller


def test_cli_run_and_refusal(fake_tools, tmp_path, capsys):
    a = tmp_path / "argv.json"
    a.write_text(json.dumps(["nmap", "q"]))
    assert vg_exec.main(["run", "--tool", "nmap", "--argv-json", str(a), "--step", "c1",
                         "--work-root", str(fake_tools)]) == 0
    assert json.loads(capsys.readouterr().out)["returncode"] == 3
    a.write_text(json.dumps(["sh", "-c", "id"]))
    assert vg_exec.main(["run", "--tool", "sh", "--argv-json", str(a), "--work-root", str(fake_tools)]) == 2
    a.write_text("not json")
    assert vg_exec.main(["run", "--tool", "nmap", "--argv-json", str(a), "--work-root", str(fake_tools)]) == 2


def test_self_test_reports_missing(fake_tools, monkeypatch, capsys):
    bindir = Path(vg_exec.SEARCH_PATH)
    for n in ("nmap", "ffuf"):  # tool giả in version
        (bindir / n).write_text("#!/bin/sh\necho 'tool version 1.2.3'\n")
    res = vg_exec.self_test()  # thiếu nuclei/sqlmap/katana/httpx
    assert set(res["missing"]) == {"nuclei", "sqlmap", "katana", "httpx"}
    assert res["nmap"] == "tool version 1.2.3"
    assert vg_exec.main(["--self-test"]) == 1
    for n in ("nuclei", "sqlmap", "katana", "httpx"):
        (bindir / n).write_text("#!/bin/sh\necho 'v 9.9'\n")
        (bindir / n).chmod(0o755)
    assert vg_exec.main(["--self-test"]) == 0


# ── vg_http ────────────────────────────────────────────────────────────────
httpx = pytest.importorskip("httpx")


def test_vg_http_never_follows_redirects():
    vg_http = _load("vg_http")
    calls = []

    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(302, headers={"location": "http://evil.example/"})

    r = vg_http.perform({"method": "GET", "url": "http://in-scope.test/"}, transport=httpx.MockTransport(handler))
    assert r["status"] == 302 and calls == ["http://in-scope.test/"]


def test_vg_http_rejects_bad_input_and_truncates():
    vg_http = _load("vg_http")
    t = httpx.MockTransport(lambda req: httpx.Response(200, content=b"a" * (vg_http.MAX_BODY + 10)))
    assert "error" in vg_http.perform({"url": "file:///etc/passwd"}, transport=t)
    assert "error" in vg_http.perform({"url": "http://x/", "method": "TRACE"}, transport=t)
    assert "error" in vg_http.perform({"url": "http://x/", "headers": {"a": 1}}, transport=t)
    r = vg_http.perform({"url": "http://x/"}, transport=t)
    assert r["body_truncated"] is True and len(r["body"]) == vg_http.MAX_BODY


# ── Dockerfile hardening (tĩnh) ────────────────────────────────────────────
def test_dockerfile_invariants():
    text = (DIR / "Dockerfile").read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert re.search(r"^FROM debian:bookworm-slim@sha256:[0-9a-f]{64} AS base", code, re.M)  # pin digest
    assert ":latest" not in code
    # target cuối (mặc định) là runner, không phải browser
    assert re.findall(r"^FROM .* AS (\w+)", code, re.M) == ["base", "browser", "runner"]
    # mọi stage cuối chạy non-root và ENTRYPOINT idle
    for stage in code.split("\nFROM ")[2:]:
        assert "USER 10002:10002" in stage
        assert 'ENTRYPOINT ["/usr/local/bin/vg-exec","--idle"]' in stage
    assert "USER root" not in code and "HEALTHCHECK" not in code
    assert "/usr/sbin/nologin" in code
    # binary tải về đều có sha256
    assert code.count("sha256sum -c") >= 4
