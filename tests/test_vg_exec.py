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
    assert re.findall(r"^FROM .* AS (\w+)", code, re.M) == ["fetch", "base", "browser", "runner"]
    # mọi stage cuối chạy non-root và ENTRYPOINT idle
    for stage in code.split("\nFROM ")[3:]:
        assert "USER 10002:10002" in stage
        assert 'ENTRYPOINT ["/usr/local/bin/vg-exec","--idle"]' in stage
    assert "USER root" not in code and "HEALTHCHECK" not in code
    assert "/usr/sbin/nologin" in code
    # binary tải về đều có sha256
    assert code.count("sha256sum -c") >= 4


# ── cờ nguy hiểm (defence in depth) ────────────────────────────────────────
@pytest.mark.parametrize("argv", [
    ["sqlmap", "-u", "http://x/?id=1", "--eval", "import os"], ["sqlmap", "--eval=import os"],
    ["sqlmap", "--ev", "x"], ["sqlmap", "--os-shell"], ["sqlmap", "--os-cmd=id"], 
    ["sqlmap", "--file-read=/etc/passwd"], ["sqlmap", "--file-write", "a"], ["sqlmap", "--sql-shell"],
    ["sqlmap", "--sql-file=a"], ["sqlmap", "--priv-esc"], ["sqlmap", "--reg-read"], ["sqlmap", "-r", "req.txt"],
    ["sqlmap", "-rreq.txt"], ["sqlmap", "-c", "x.conf"], ["sqlmap", "--tamper=/work/x.py"],
    ["sqlmap", "--tamper", "../x"], ["sqlmap", "--output-dir=/tmp"], ["sqlmap", "--update"], ["sqlmap", "-g", "q"],
    ["sqlmap", "--OS-SHELL"],
    ["nmap", "--script", "/work/x.nse", "h"], ["nmap", "--script=./x.nse", "h"], ["nmap", "--script=vuln,exploit", "h"],
    ["nmap", "--script", "default,http-*", "h"], ["nmap", "--script"], ["nmap", "--scri=evil", "h"],
    ["nmap", "--script-args=a=b", "h"], ["nmap", "--script-args-file", "f"], ["nmap", "--script-updatedb"],
    ["nmap", "--datadir=/work"], ["nmap", "--dat", "/work"], ["nmap", "-iL", "/etc/passwd"], ["nmap", "-iLfile"],
    ["nmap", "--resume", "log"], ["nmap", "--stylesheet=x"], ["nmap", "-oN", "/tmp/x"], ["nmap", "-oX/etc/x"],
    ["nmap", "-oN", "/work/../tmp/x"], ["nmap", "-oN", "rel.txt"],
    ["nuclei", "-code"], ["nuclei", "--code"], ["nuclei", "-t", "/work/x.yaml"], ["nuclei", "-t=/tmp/x"],
    ["nuclei", "-t", "/opt/nuclei-templates/../../work/x"], ["nuclei", "-templates", "/opt/nuclei-templates,/work/x"],
    ["nuclei", "-w", "/work/wf"], ["nuclei", "-ut"], ["nuclei", "-ud", "/work"], ["nuclei", "-tu", "http://e"],
    ["nuclei", "-l", "/etc/hosts"], ["nuclei", "-config", "/work/c"], ["nuclei", "-t"],
    ["ffuf", "-input-cmd", "id"], ["ffuf", "--input-cmd=id"],
])
def test_dangerous_flags_refused(argv):
    with pytest.raises(vg_exec.ExecRefused):
        vg_exec.validate_argv(argv)


@pytest.mark.parametrize("argv", [
    ["sqlmap", "-u", "http://x/?id=1", "--batch", "--level=2", "--risk", "1", "--forms", "--dbs"],
    ["sqlmap", "--tamper=space2comment,between", "-u", "http://x"],
    ["sqlmap", "--technique=BEU", "--data", "a=1", "--random-agent", "--sql-query=select 1"],
    ["nmap", "-sV", "-Pn", "-p", "80,443", "--top-ports", "100", "10.0.0.1"],
    ["nmap", "-sC", "--script=default,safe", "h"], ["nmap", "--script", "http-title,ssl-cert", "h"],
    ["nmap", "-oX", "/work/s1/out.xml", "h"], ["nmap", "-oN/work/s1/out.txt", "h"], ["nmap", "-oX", "-", "h"],
    ["nuclei", "-u", "http://x", "-t", "/opt/nuclei-templates/http/", "-duc", "-ni", "-dr"],
    ["nuclei", "-u", "http://x", "-t=/opt/nuclei-templates/cves,/opt/nuclei-templates/http", "-rl", "50"],
    ["nuclei", "-l", "/work/s1/targets.txt", "-o", "/work/s1/out.jsonl", "-jsonl"],
    ["ffuf", "-u", "http://x/FUZZ", "-w", "/usr/share/seclists/x.txt", "-rate", "10"],
])
def test_legit_flags_allowed(argv):
    assert vg_exec.validate_argv(argv) == argv


def test_nuclei_always_gets_duc(fake_tools, monkeypatch):
    (Path(vg_exec.SEARCH_PATH) / "nuclei").write_text('#!/bin/sh\necho "$@"\n')
    (Path(vg_exec.SEARCH_PATH) / "nuclei").chmod(0o755)
    res = vg_exec.run_step(["nuclei", "-u", "http://x"], step="n1", work_root=str(fake_tools))
    assert Path(res["stdout_path"]).read_text().split() == ["-u", "http://x", "-duc"]
    res = vg_exec.run_step(["nuclei", "-u", "http://x", "-duc"], step="n2", work_root=str(fake_tools))
    assert Path(res["stdout_path"]).read_text().split().count("-duc") == 1


# ── helper python: không bao giờ thực thi vg_http.py từ cwd ────────────────
def test_python_helper_runs_isolated_and_ignores_planted_module(fake_tools, tmp_path, monkeypatch):
    mods = tmp_path / "mods"
    mods.mkdir()
    (mods / "vg_http.py").write_text("import sys\nprint('REAL', sys.argv[1:])\n")
    bindir = Path(vg_exec.SEARCH_PATH)
    (bindir / "python3").symlink_to(sys.executable)
    monkeypatch.setattr(vg_exec, "MODULE_DIR", str(mods))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "evil"))  # cũng không được dùng
    step = fake_tools / "p1"
    step.mkdir(parents=True)
    (step / "vg_http.py").write_text("print('HIJACKED')\n")  # cài sẵn trong cwd của bước
    res = vg_exec.run_step(["python3", "-m", "vg_http", "--x"], tool="python3 -m vg_http", step="p1",
                           work_root=str(fake_tools))
    out = Path(res["stdout_path"]).read_text()
    assert res["returncode"] == 0 and out.startswith("REAL") and "HIJACKED" not in out and "'--x'" in out


def test_python_helper_missing_module_refused(fake_tools, tmp_path, monkeypatch):
    (Path(vg_exec.SEARCH_PATH) / "python3").symlink_to(sys.executable)
    monkeypatch.setattr(vg_exec, "MODULE_DIR", str(tmp_path / "empty"))
    with pytest.raises(vg_exec.ExecRefused, match="not installed"):
        vg_exec.run_step(["python3", "-m", "vg_http"], step="p2", work_root=str(fake_tools))


def test_existing_output_symlink_not_followed(fake_tools, tmp_path):
    step = fake_tools / "l1"
    step.mkdir(parents=True)
    target = tmp_path / "victim"
    (step / "stdout").symlink_to(target)
    with pytest.raises(OSError):
        vg_exec.run_step(["nmap", "x"], step="l1", work_root=str(fake_tools))
    assert not target.exists()


def test_vg_http_timeout_validation():
    vg_http = _load("vg_http")
    t = httpx.MockTransport(lambda req: httpx.Response(200))
    for bad in (-1, 0, float("nan"), float("inf"), "x", 10_000):
        assert "error" in vg_http.perform({"url": "http://x/", "timeout": bad}, transport=t)
    assert "error" in vg_http.perform({"url": "http://x/", "body": "a" * (vg_http.MAX_BODY + 1)}, transport=t)
    assert vg_http.perform({"url": "http://x/", "timeout": 5}, transport=t)["status"] == 200


def test_dockerfile_pins_and_minimal_image():
    code = (DIR / "Dockerfile").read_text()
    assert code.splitlines()[0] == "# syntax=docker/dockerfile:1"
    assert re.search(r"NUCLEI_TEMPLATES_COMMIT=[0-9a-f]{40}", code)
    final = code.split("AS base")[1]
    assert not re.search(r"apt-get install[^&]*\b(curl|unzip|git)\b", final.split("AS browser")[0])
    assert code.count("perm /6000") >= 2  # base + browser


# ── cờ ngắn gộp / option một gạch (vòng re-verify) ─────────────────────────
@pytest.mark.parametrize("argv", [
    # sqlmap: cờ ngắn gộp — `-br file` = -b -r file (đã tái hiện trên sqlmap thật)
    ["sqlmap", "-br", "/work/req.txt", "--batch"], ["sqlmap", "-bc", "x.conf"], ["sqlmap", "-vr", "req.txt"],
    ["sqlmap", "-bl", "log"], ["sqlmap", "-bm", "bulk"], ["sqlmap", "-bg", "dork"], ["sqlmap", "-bd", "mysql://x"],
    ["sqlmap", "-bs", "/work/s.sqlite"], ["sqlmap", "-bt", "/work/t.txt"], ["sqlmap", "-obr", "f"],
    ["sqlmap", "-rreq.txt"], ["sqlmap", "-s", "/work/s.sqlite"], ["sqlmap", "-t", "/work/traffic.txt"],
    ["sqlmap", "-z", "flu,bat"], ["sqlmap", "-u", "http://x/?a=1", "-r", "f"],
    ["sqlmap", "-u", "http://x/", "--batch", "-hh"], ["sqlmap", "-u"],            # thiếu giá trị
    ["sqlmap", "--batch=1"], ["sqlmap", "http://x/"], ["sqlmap", "--", "-u"],     # cờ không nhận giá trị / positional
    ["sqlmap", "--dump-fil=/work/x"], ["sqlmap", "--dump-file=/work/x"], ["sqlmap", "--alert=id"],
    ["sqlmap", "--preprocess=/work/p.py"], ["sqlmap", "--save=/work/c.ini"], ["sqlmap", "--live-cookies=/etc/x"],
    ["sqlmap", "--safe-req=f"], ["sqlmap", "--second-req=f"], ["sqlmap", "--shell"], ["sqlmap", "--check-internet"],
    ["sqlmap", "--bat"], ["sqlmap", "--BATCH"], ["sqlmap", "--results-file=/work/r"], ["sqlmap", "--udf-inject"],
    # nmap: cụm cờ ngắn, option dài MỘT gạch (getopt_long_only), viết tắt
    ["nmap", "-ni", "/etc/hosts"], ["nmap", "-sLi/tmp/h"], ["nmap", "-i", "f"], ["nmap", "-iL", "f"],
    ["nmap", "-script=/work/x.nse", "h"], ["nmap", "-script", "banner", "h"], ["nmap", "-resume", "f"],
    ["nmap", "-datadir=/work"], ["nmap", "-nvoN", "/tmp/o"], ["nmap", "-noN", "/work/o"], ["nmap", "-sI", "z"],
    ["nmap", "--open-x"], ["nmap", "--op"], ["nmap", "-e", "eth0"], ["nmap", "-D", "a,b"], ["nmap", "-S", "1.1.1.1"],
    ["nmap", "-b", "ftp"], ["nmap", "--proxies", "x"], ["nmap", "-oN"], ["nmap", "--top-ports"],
    ["nmap", "--top-ports=1;id"], ["nmap", "-p", "80;id"], ["nmap", "--"], ["nmap", "-"],
])
def test_bundled_and_single_dash_bypasses_refused(argv):
    with pytest.raises(vg_exec.ExecRefused):
        vg_exec.validate_argv(argv)


@pytest.mark.parametrize("argv", [
    # dạng argv thật mà toolbelt/LLM sinh ra
    ["sqlmap", "-u", "http://x/?id=1", "--batch", "--level=3", "--risk=2", "--dbs", "--technique=BEUSTQ"],
    ["sqlmap", "-u", "http://x/", "--data=id=1", "--cookie=a=b", "-p", "id", "--dbms=mysql", "--random-agent"],
    ["sqlmap", "-uhttp://x/?id=1", "-pid", "-v3", "--batch"], ["sqlmap", "-u", "http://x/", "-bf", "-a"],
    ["sqlmap", "-u", "http://x/", "-D", "app", "-T", "users", "-C", "id,name", "--dump", "--threads=4"],
    ["sqlmap", "-u", "http://x/", "-H", "X-A: b", "-A", "ua", "--proxy=http://gw:8080", "--timeout=10"],
    ["sqlmap", "-u", "http://x/", "--tamper=space2comment", "--os=Linux", "--sql-query=select 1"],
    ["nmap", "-Pn", "-n", "-sT", "-sV", "-p", "80,443,8080", "-T3", "--open", "--max-hostgroup", "1", "10.0.0.5"],
    ["nmap", "-Pn", "-n", "-sT", "-sV", "--top-ports", "100", "-T3", "--open", "--max-hostgroup=1", "app.lab"],
    ["nmap", "-p80,443", "-sV", "-vv", "-oX", "/work/s1/scan.xml", "h"], ["nmap", "-sC", "-sV", "-A", "-F", "h"],
    ["nmap", "-PS80,443", "-PE", "--reason", "--host-timeout", "30s", "10.0.0.0/30"],
])
def test_real_argument_forms_allowed(argv):
    assert vg_exec.validate_argv(argv) == argv


def test_sqlmap_option_table_matches_real_sqlmap():
    """Mọi option dài trong bảng allowlist phải là option sqlmap thật; không option nguy hiểm nào lọt vào."""
    dangerous = {"eval", "os-cmd", "os-shell", "os-pwn", "file-read", "file-write", "sql-shell", "sql-file", "alert",
                 "preprocess", "postprocess", "shell", "update", "save", "har", "output-dir", "dump-file",
                 "tmp-dir", "load-cookies", "live-cookies", "safe-req", "second-req", "proxy-file", "auth-file",
                 "shared-lib", "results-file", "check-internet", "udf-inject", "purge", "wizard", "google-dork"}
    assert not dangerous & set(vg_exec.SQLMAP_LONG)
    assert not set("rclmgdstzh") & set(vg_exec.SQLMAP_SHORT)
