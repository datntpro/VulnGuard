"""Probe self-tests (#101 PR-C): the reachability probe must not be vacuous."""
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("reach_check", ROOT / "scripts" / "scanner_reachability" / "check.py")
chk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chk)


def test_vulnerable_call_from_console_script_frame_is_flagged_run():
    # fake `wcmatch` called via <module> -> main() (console-script shape) is RUN; its import-time call is IMPORT
    assert chk.positive_control()


def test_probe_without_control_activity_fails():
    ok, _ = chk.run_probed([sys.executable, "-c", "pass"], ["/wcmatch/"], re.compile("^wcmatch/"), "t",
                           "semgrep/core_runner.py")
    assert not ok  # nothing ran in the control module -> vacuous -> must fail


def test_semgrep_result_guard():
    class P:
        returncode = 2
        stdout = '{"results": []}'
        stderr = ""
    assert not chk.semgrep_result_ok(P, "t")
    P.returncode, P.stdout = 1, '{"results": [{"check_id": "x"}]}'
    assert chk.semgrep_result_ok(P, "t")
