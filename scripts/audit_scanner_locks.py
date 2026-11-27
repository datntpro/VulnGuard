#!/usr/bin/env python3
"""pip-audit gate over docker/scanners/*.txt with expiring, evidenced ignores (#101 PR-C).

Fails on: an unignored vulnerability, an expired ignore, an ignore missing a required field
or with expiry > 120 days after `added`. Warns on stale ignores (id no longer reported).
An ignore applies only while package==version matches what the lock reports.
Stdlib only (tomllib: Python >= 3.11).
"""
import argparse
import datetime as dt
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCKS = ["semgrep", "bandit", "checkov", "pip-audit"]
REQUIRED = ["id", "lock", "package", "version", "reason", "evidence", "added", "expires", "tracking"]
MAX_DAYS = 120


def load_ignores(path):
    with open(path, "rb") as fh:
        return tomllib.load(fh).get("ignore", [])


def validate(entries, today):
    """Return (valid_unexpired_entries, errors)."""
    errors, ok = [], []
    for e in entries:
        eid = e.get("id", "<no id>")
        missing = [k for k in REQUIRED if not str(e.get(k, "")).strip()]
        if missing:
            errors.append(f"ignore {eid}: missing field(s) {', '.join(missing)}")
            continue
        if e["lock"] not in LOCKS:
            errors.append(f"ignore {eid}: unknown lock {e['lock']!r}")
            continue
        added, expires = e["added"], e["expires"]
        if not (isinstance(added, dt.date) and isinstance(expires, dt.date)):
            errors.append(f"ignore {eid}: added/expires must be TOML dates")
            continue
        if (expires - added).days > MAX_DAYS:
            errors.append(f"ignore {eid}: expires {expires} is more than {MAX_DAYS} days after added {added}")
            continue
        if expires < today:
            errors.append(f"ignore {eid} expired {expires}: re-verify reachability or bump the lock")
            continue
        ok.append(e)
    return ok, errors


def run_pip_audit(pip_audit, lock_file, ids):
    cmd = [pip_audit, "-r", str(lock_file), "--require-hashes", "--disable-pip",
           "--progress-spinner", "off", "-f", "json"]
    for i in ids:
        cmd += ["--ignore-vuln", i]
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise SystemExit(f"pip-audit failed on {lock_file} (exit {p.returncode}): {p.stderr[-800:]}")


def evaluate(lock, entries, report):
    """Pure check of one lock. Returns (errors, warnings, applied_ids).

    `report` is pip-audit JSON produced WITHOUT --ignore-vuln, so the version/stale logic is ours."""
    errors, warnings, applied = [], [], []
    pins = {d["name"].lower(): d["version"] for d in report.get("dependencies", [])}
    matched = set()
    for dep in report.get("dependencies", []):
        for v in dep.get("vulns", []):
            ids = {v["id"], *v.get("aliases", [])}
            hit = [e for e in entries if e["package"].lower() == dep["name"].lower()
                   and ({e["id"], *e.get("aliases", [])} & ids)]
            if not hit:
                errors.append(f"[{lock}] {dep['name']}=={dep['version']} {v['id']} is not ignored "
                              f"(fix: {', '.join(v.get('fix_versions') or []) or 'none'})")
            elif hit[0]["version"] != dep["version"]:
                errors.append(f"[{lock}] ignore {hit[0]['id']} is for {dep['name']}=={hit[0]['version']} "
                              f"but the lock pins {dep['version']}: re-verify reachability")
            else:
                matched.add(hit[0]["id"])
                applied.append(v["id"])
    for e in entries:
        if e["id"] not in matched and not any(e["id"] == x for x in applied):
            warnings.append(f"[{lock}] ignore {e['id']} ({e['package']}=={e['version']}) is no longer reported "
                            f"(lock pins {pins.get(e['package'].lower(), 'nothing')}): remove the entry")
    return errors, warnings, applied


def main(argv=None, audit=run_pip_audit, today=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pip-audit", default="pip-audit")
    ap.add_argument("--locks-dir", default=str(ROOT / "docker" / "scanners"))
    ap.add_argument("--ignores", default=None)
    a = ap.parse_args(argv)
    locks_dir = Path(a.locks_dir)
    today = today or dt.datetime.now(dt.timezone.utc).date()
    entries = load_ignores(a.ignores or locks_dir / "audit-ignores.toml")
    valid, errors = validate(entries, today)
    warnings = []
    for lock in LOCKS:
        mine = [e for e in valid if e["lock"] == lock]
        report = audit(a.pip_audit, locks_dir / f"{lock}.txt", [])
        e, w, applied = evaluate(lock, mine, report)
        errors += e
        warnings += w
        print(f"{lock}.txt: {len(report.get('dependencies', []))} packages, "
              f"ignored {len(applied)} vuln(s): {', '.join(sorted(set(applied))) or '-'}")
    for w in warnings:
        print(f"WARNING: {w}")
    for e in errors:
        print(f"ERROR: {e}")
    if errors:
        return 1
    print("scanner locks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
