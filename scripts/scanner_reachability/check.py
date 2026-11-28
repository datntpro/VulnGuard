"""Reachability check for the audit-ignores in docker/scanners/audit-ignores.toml (#101 PR-C).

Runs the REAL production semgrep argv (captured from SemgrepScanner._run_semgrep) and the
real checkov argv under the sitecustomize.py probe, then fails if code of an ignored,
vulnerable dependency is *executed* (RUN) during a scan. Import-time execution (a `<frozen importlib` frame on the stack) is allowed
(pysemgrep imports mcp at module level) - that is exactly what the ignore justifications say.

Usage (repo root):  python scripts/scanner_reachability/check.py [--fixtures tests/fixtures] [--online]
In the image:       docker run ... -v $PWD/scripts/scanner_reachability:/probe:ro -v $PWD/tests/fixtures:/fx:ro \
                      --entrypoint python vulnguard-api:pdfcheck /probe/check.py --fixtures /fx
"""
import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

PROBE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.getcwd())  # image WORKDIR=/app; `python script.py` does not add cwd

SEMGREP_WATCH = ["/site-packages/mcp/", "/wcmatch/", "/opentelemetry/propagate",
                 "/opentelemetry/trace/propagation/tracecontext", "/opentelemetry/trace/span.py",
                 "/semgrep/core_runner.py"]  # last one = positive control (always executed by a scan)
CHECKOV_WATCH = ["/soupsieve/", "/bs4/", "/ecdsa/", "/checkov/common/runners/runner_registry.py"]
# RUN-time calls that make an ignore invalid. Local-context reads such as get_current_span /
# get_span_context / is_valid are NOT header parsing and are allowed.
SEMGREP_FORBIDDEN = re.compile(r"^(mcp/|wcmatch/)|:(from_header|extract)$")
# wcmatch IS reached in registry mode (rule `paths:` globs, ~650 globmatch calls): documented in the
# CVE-2026-132276 entry. It stays forbidden for the offline/bundled scan.
SEMGREP_REGISTRY_FORBIDDEN = re.compile(r"^mcp/|:(from_header|extract)$")
CHECKOV_FORBIDDEN = re.compile(r"^(soupsieve/|bs4/|ecdsa/)")
# Positive controls: code the tool certainly executes. If the probe sees no RUN call here it is vacuous.
SEMGREP_CONTROL_RUN = "semgrep/core_runner.py"
CHECKOV_CONTROL_RUN = "checkov/common/runners/runner_registry.py"

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
        return 0, "{}", ""

    orig = iac.run_command
    iac.run_command = fake
    try:
        asyncio.run(iac.CheckovScanner(scan_path).scan())
    finally:
        iac.run_command = orig
    return captured[0]


def parse_probe(lines):
    loaded = [ln for ln in lines if ln.startswith("loaded pid=")]
    imports = [ln[7:] for ln in lines if ln.startswith("IMPORT ")]
    runs = [ln[4:] for ln in lines if ln.startswith("RUN ")]
    return loaded, imports, runs


def run_probed(argv, watch, forbidden, label, control_run, require_import=None, timeout=600):
    """Run argv under the probe. Returns (ok, CompletedProcess). Fails when a forbidden call RUNs,
    or when a positive control is missing (the probe/scan would be vacuous)."""
    out = tempfile.NamedTemporaryFile(prefix="vgprobe-", suffix=".txt", delete=False)
    out.close()
    home = tempfile.mkdtemp(prefix="vghome-")  # read-only rootfs + root-owned tmpfs HOME crashed policy_sentry
    env = dict(os.environ, PYTHONPATH=PROBE_DIR + os.pathsep + os.environ.get("PYTHONPATH", ""),
               VG_PROBE_WATCH=",".join(watch), VG_PROBE_OUT=out.name, HOME=home,
               XDG_CACHE_HOME=home + "/.cache", XDG_CONFIG_HOME=home + "/.config", XDG_DATA_HOME=home + "/.local", SEMGREP_HOME=home + "/.semgrep")
    p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    lines = open(out.name, encoding="utf-8").read().splitlines()
    os.unlink(out.name)
    shutil.rmtree(home, ignore_errors=True)
    loaded, imports, runs = parse_probe(lines)
    bad = [r for r in runs if forbidden.search(r)]
    print(f"[{label}] exit={p.returncode} probe_loaded_in={len(loaded)} process(es) "
          f"IMPORT_keys={len(imports)} RUN_keys={len(runs)} forbidden={len(bad)}")
    for r in runs:
        print(f"    RUN {r}{'   <-- FORBIDDEN' if r in bad else ''}")
    ok = not bad
    if not any(control_run in r for r in runs):
        print(f"[{label}] FAIL: positive control missing - no RUN call in {control_run}; probe is vacuous or the tool did not run")
        ok = False
        print(f"    stdout tail: {p.stdout[-800:]!r}")
        print(f"    stderr tail: {p.stderr[-1500:]!r}")
    if require_import and not any(ln.startswith(require_import) for ln in imports):
        print(f"[{label}] FAIL: expected IMPORT calls in {require_import}* (pysemgrep path not exercised); probe unproven")
        ok = False
    return ok, p


def positive_control():
    """Prove the probe can see a vulnerable-module call: a fake `wcmatch` package called from a console-script
    style `<module>` -> main() (must be RUN) and from its own import (must be IMPORT)."""
    d = tempfile.mkdtemp(prefix="vgctl-")
    try:
        pkg = os.path.join(d, "site-packages", "wcmatch")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "__init__.py"), "w") as fh:
            fh.write("def at_import():\n    return 1\n\ndef globmatch():\n    return 2\n\nat_import()\n")
        script = os.path.join(d, "entry.py")
        with open(script, "w") as fh:
            fh.write("import sys\nsys.path.insert(0, %r)\nimport wcmatch\n\ndef main():\n    wcmatch.globmatch()\n    return 0\n\n"
                     "sys.exit(main())\n" % os.path.join(d, "site-packages"))
        outf = os.path.join(d, "out.txt")
        env = dict(os.environ, PYTHONPATH=PROBE_DIR, VG_PROBE_WATCH="/wcmatch/", VG_PROBE_OUT=outf)
        subprocess.run([sys.executable, script], env=env, check=True, capture_output=True, timeout=60)
        _, imports, runs = parse_probe(open(outf, encoding="utf-8").read().splitlines())
        return any(r.startswith("wcmatch/__init__.py:globmatch") for r in runs) and \
            any(i.startswith("wcmatch/__init__.py:at_import") for i in imports) and \
            not any("at_import" in r for r in runs)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def semgrep_result_ok(p, label):
    """The probed scan itself must have worked: exit 0/1 and parseable JSON with >=1 result."""
    try:
        n = len(json.loads(p.stdout).get("results", []))
    except ValueError:
        n = -1
    if p.returncode not in (0, 1) or n < 1:
        print(f"[{label}] FAIL: scan did not work (exit {p.returncode}, results={n}); stderr: {p.stderr[-600:]}")
        return False
    print(f"[{label}] scan produced {n} result(s)")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="tests/fixtures")
    ap.add_argument("--online", action="store_true", help="also run the registry rulesets (needs network)")
    a = ap.parse_args()

    if not positive_control():
        print("FAIL: probe self-check - a fake vulnerable-module call from a console-script frame was not flagged RUN")
        return 1
    print("[probe self-check] RUN/IMPORT classification OK")

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
            forb = SEMGREP_REGISTRY_FORBIDDEN if "registry" in label else SEMGREP_FORBIDDEN
            good, p = run_probed(argv, SEMGREP_WATCH, forb, label, SEMGREP_CONTROL_RUN,
                                 require_import="mcp/")
            ok &= good and semgrep_result_ok(p, label)
        good, p = run_probed(capture_checkov_argv(iac_dir), CHECKOV_WATCH, CHECKOV_FORBIDDEN, "checkov",
                             CHECKOV_CONTROL_RUN)
        ok &= good
        if "failed_checks" not in p.stdout:
            print("[checkov] FAIL: no failed_checks in output - checkov did not scan the fixture")
            print("    stdout tail:", p.stdout[-600:].replace("\n", " | "))
            print("    stderr tail:", p.stderr[-1200:].replace("\n", " | "))
            ok = False
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("REACHABILITY OK" if ok else "REACHABILITY FAILED: an ignored advisory is now reachable or the probe is vacuous - re-verify docker/scanners/audit-ignores.toml")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
