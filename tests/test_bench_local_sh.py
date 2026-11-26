"""P2-15b (fix M2): eval/bench/bench-local.sh — BENCH_TASKS rỗng/không đặt, và exit code thật được truyền ra (trap không che lỗi).
Chạy script THẬT bằng bash (ưu tiên /bin/bash = 3.2 trên macOS) với curl/docker/python giả trong PATH — không Docker, không mạng."""
import os
import shutil
import stat
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "eval/bench/bench-local.sh")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")


def _exe(path, body):
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


@pytest.fixture
def fake(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    log = tmp_path / "calls.log"
    _exe(b / "curl", 'echo \'{"models":[{"name":"qwen2.5:7b"}]}\'\n')
    _exe(b / "docker", f'echo "docker $*" >> "{log}"\nexit 0\n')
    _exe(b / "py", f'echo "py $*" >> "{log}"\ncase "$*" in *"$FAIL_ON"*) [ -n "$FAIL_ON" ] && exit 7;; esac\nexit 0\n')
    return b, log


def _run(fake, **env):
    b, log = fake
    e = {"PATH": f"{b}:/usr/bin:/bin", "PY": str(b / "py"), "BENCH_SUITE": "stub,injection", "BENCH_OUT": "out-test", "FAIL_ON": ""}
    e.update(env)
    r = subprocess.run([BASH, SCRIPT], cwd=ROOT, env=e, capture_output=True, text=True, timeout=60)
    return r, log.read_text() if log.exists() else ""


def test_empty_bench_tasks_runs_to_completion_without_tasks_flag(fake):
    r, calls = _run(fake, BENCH_TASKS="")
    assert r.returncode == 0, r.stderr
    assert "unbound" not in r.stderr
    assert "--driver real" in calls and "--check-safety" in calls          # thật sự chạy, không thoát sớm
    assert "--tasks" not in calls
    assert "compose" in calls and "down -v" in calls                       # trap vẫn dọn lab


def test_unset_bench_tasks_uses_default_task_list(fake):
    r, calls = _run(fake)
    assert r.returncode == 0, r.stderr
    assert "--tasks XBEN-004-24,XBEN-005-24,XBEN-007-24" in calls


@pytest.mark.parametrize("fail_on", ["--driver", "--check-safety"])
def test_failing_run_propagates_nonzero_exit_and_still_cleans_up(fake, fail_on):
    r, calls = _run(fake, BENCH_TASKS="", FAIL_ON=fail_on)
    assert r.returncode == 7                                               # exit code thật, không bị trap biến thành 0
    assert "down -v" in calls


def test_missing_ollama_model_exits_nonzero(fake):
    b, _ = fake
    _exe(b / "curl", "exit 22\n")
    r, calls = _run(fake, BENCH_TASKS="")
    assert r.returncode != 0 and "--driver" not in calls
