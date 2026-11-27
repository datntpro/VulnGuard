"""Reachability check for the audit-ignores in docker/scanners/audit-ignores.toml (#101 PR-C).

Runs the REAL production semgrep argv (captured from SemgrepScanner._run_semgrep) and the
real checkov argv under the sitecustomize.py probe, then fails if code of an ignored,
vulnerable dependency is *executed* (RUN) during a scan. Import-time execution is allowed
(pysemgrep imports mcp at module level) - that is exactly what the ignore justifications say.

Usage (repo root):  python scripts/scanner_reachability/check.py [--fixtures tests/fixtures] [--online]
In the image:       docker run ... -v $PWD/scripts/scanner_reachability:/probe:ro -v $PWD/tests/fixtures:/fx:ro \
                      --entrypoint python vulnguard-api:pdfcheck /probe/check.py --fixtures /fx
"""
import argparse
import asyncio
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROBE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.getcwd())  # image WORKDIR=/app; `python script.py` does not add cwd

SEMGREP_WATCH = ["/site-packages/mcp/", "/wcmatch/", "/opentelemetry/propagate",
                 "/opentelemetry/trace/propagation/tracecontext", "/opentelemetry/trace/span.py"]
CHECKOV_WATCH = ["/soupsieve/", "/bs4/", "/asteval/", "/ecdsa/"]
# RUN-time calls that make an ignore invalid. Local-context reads such as get_current_span /
# get_span_context / is_valid are NOT header parsing and are allowed.
SEMGREP_FORBIDDEN = re.compile(r"^(mcp/|wcmatch/)|:(from_header|extract)$")
# asteval is legitimately used by checkov (variable rendering) -> only soupsieve/bs4/ecdsa forbidden.
CHECKOV_FORBIDDEN = re.compile(r"^(soupsieve/|bs4/|ecdsa/)")

TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "probe-bucket"\n  acl    = "public-read"\n}\n'


def capture_semgrep_argv(scan_path, config_args):
    """The exact argv SemgrepScanner would run (PYTHONPATH is scrubbed by run_command, so we exec it ourselves)."""
    from scanner.scanners import sast
    captured = []

    async def fake(cmd, **kw):
        captured.append(cmd)
        return 0, '{"results": []}', ""

    orig = sast.run_command
    sast.run_command = fake
    try:
        asyncio.run(sast.SemgrepScanner(scan_path)._run_semgrep(config_args))
    finally:
        sast.run_command = orig
    return captured[0]


def capture_checkov_argv(scan_path):
    from scanner.scanners import iac
    captured = []

    async def fake(cmd, **kw):
        captured.append(cmd)
        return 0, "", ""

    orig = iac.run_command
    iac.run_command = fake
    try:
        asyncio.run(iac.CheckovScanner(scan_path).scan())
    finally:
        iac.run_command = orig
    return captured[0]


def run_probed(argv, watch, forbidden, label, timeout=600):
    out = tempfile.NamedTemporaryFile(prefix="vgprobe-", suffix=".txt", delete=False)
    out.close()
    env = dict(os.environ, PYTHONPATH=PROBE_DIR + os.pathsep + os.environ.get("PYTHONPATH", ""),
               VG_PROBE_WATCH=",".join(watch), VG_PROBE_OUT=out.name)
    env.setdefault("HOME", tempfile.gettempdir())
    p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    lines = open(out.name, encoding="utf-8").read().splitlines()
    os.unlink(out.name)
    loaded = [ln for ln in lines if ln.startswith("loaded pid=")]
    runs = [ln[4:] for ln in lines if ln.startswith("RUN ")]
    bad = [r for r in runs if forbidden.search(r)]
    print(f"[{label}] exit={p.returncode} probe_loaded_in={len(loaded)} process(es) RUN_calls={len(runs)} forbidden={len(bad)}")
    for r in runs:
        print(f"    RUN {r}{'   <-- FORBIDDEN' if r in bad else ''}")
    if not loaded:
        print(f"[{label}] probe never loaded (tool is not a Python process in this build): nothing imported, PASS")
    return not bad, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="tests/fixtures")
    ap.add_argument("--online", action="store_true", help="also run the registry rulesets (needs network)")
    a = ap.parse_args()

    from scanner.scanners.sast import BUNDLED_RULES_DIR
    rules = os.path.join(BUNDLED_RULES_DIR, "python-security.yaml")
    work = tempfile.mkdtemp(prefix="vgreach-")
    ok = True
    try:
        # Copy OUT of any tests/ dir: semgrep's default .semgrepignore skips tests/ (scan would be vacuous).
        src = os.path.join(a.fixtures, "semgrep_rules")
        if not os.path.isdir(src):
            src = os.path.join(a.fixtures, "vulnerable")
        code = os.path.join(work, "code")
        shutil.copytree(src, code)
        iac_dir = os.path.join(work, "iac")
        os.makedirs(iac_dir)
        with open(os.path.join(iac_dir, "main.tf"), "w") as fh:
            fh.write(TF)

        runs = [("semgrep bundled", capture_semgrep_argv(code, ["--config", rules]))]
        if a.online:
            runs.append(("semgrep registry", capture_semgrep_argv(
                code, ["--config", "p/python", "--config", "p/security-audit", "--config", "p/owasp-top-ten"])))
        for label, argv in runs:
            good, _ = run_probed(argv, SEMGREP_WATCH, SEMGREP_FORBIDDEN, label)
            ok &= good
        good, p = run_probed(capture_checkov_argv(iac_dir), CHECKOV_WATCH, CHECKOV_FORBIDDEN, "checkov")
        ok &= good
        if "failed_checks" not in p.stdout:
            print("[checkov] no failed_checks in output - probe scan was vacuous (checkov did not scan the fixture)")
            print("    stdout tail:", p.stdout[-600:].replace("\n", " | "))
            print("    stderr tail:", p.stderr[-1200:].replace("\n", " | "))
            ok = False
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("REACHABILITY OK" if ok else "REACHABILITY FAILED: an ignored advisory is now reachable - re-verify docker/scanners/audit-ignores.toml")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
