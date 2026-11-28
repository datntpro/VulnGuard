"""Scanner smoke trong image: ``python -m scanner.scanners.selftest <fixtures-root> [--xfail a,b]``.

Chạy TỪNG scanner đóng gói sẵn (đúng class + đúng argv như production) trên fixture đã biết lỗi
và khẳng định số finding tối thiểu. Một tool hỏng im lặng (vd gitleaks từ chối ``--quiet`` → 0
secret, lock bump cài được nhưng không tìm ra gì) sẽ làm job CI đỏ. Không cần mạng.

``<fixtures-root>`` = thư mục ``tests/fixtures`` (mount RO vào container). Fixture được copy ra
thư mục tạm vì semgrep mặc định bỏ qua thư mục ``tests/``.

``--xfail`` liệt kê check đã BIẾT hỏng (có TODO trỏ PR sửa): vẫn chạy và in kết quả, nhưng không
làm exit≠0; nếu bỗng pass thì in XPASS để dọn khỏi danh sách (không làm đỏ, tránh deadlock thứ tự merge).
Exit 0 = mọi check đạt (hoặc xfail đúng như dự kiến), 1 = có check lỗi, 2 = dùng sai.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, List, Tuple

# (tên check, mô tả lỗi, số finding tối thiểu hoặc None cho check phiên bản)
Result = Tuple[str, str, str]  # (name, status, detail)


def _count(scanner_cls, path: str) -> int:
    return len(asyncio.run(scanner_cls(path).scan()))


def _version(*cmd: str) -> int:
    p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(f"`{' '.join(cmd)}` exit {p.returncode}: {(p.stderr or p.stdout).strip()[-200:]}")
    return 1


def _semgrep(root: str) -> Tuple[int, str]:
    import yaml

    from scanner.scanners.sast import BUNDLED_RULES_DIR, SemgrepScanner

    with open(os.path.join(BUNDLED_RULES_DIR, "python-security.yaml"), encoding="utf-8") as f:
        ids = [r["id"] for r in yaml.safe_load(f)["rules"]]
    findings = asyncio.run(SemgrepScanner(os.path.join(root, "semgrep_rules")).scan())
    hit = {i for i in ids if any(str(f["rule_id"]).split(".")[-1] == i for f in findings)}
    missing = sorted(set(ids) - hit)
    if missing:
        raise RuntimeError(f"rule không khớp fixture nào: {', '.join(missing)}")
    return len(findings), f"{len(ids)}/{len(ids)} rule"


def _pip_audit_isolation() -> Tuple[int, str]:
    """A target-supplied local sdist must never be built (no pip is spawned by pip-audit)."""
    import asyncio
    import tarfile

    from scanner.scanners.sca import PipAuditScanner

    td = tempfile.mkdtemp(prefix="vg-pipaudit-iso-")
    try:
        target, marker = os.path.join(td, "t"), os.path.join(td, "MARKER")
        pkg = os.path.join(td, "pkg", "canary-1.0")
        os.makedirs(pkg)
        os.makedirs(target)
        with open(os.path.join(pkg, "pyproject.toml"), "w") as f:
            f.write('[build-system]\nrequires = []\nbuild-backend = "b"\nbackend-path = ["."]\n')
        with open(os.path.join(pkg, "b.py"), "w") as f:
            f.write(f"def _m():\n    open({marker!r}, 'w').write('x')\n"
                    "def get_requires_for_build_wheel(c=None):\n    _m(); return []\n"
                    "def build_wheel(*a, **k):\n    _m(); raise SystemExit(1)\n"
                    "def prepare_metadata_for_build_wheel(*a, **k):\n    _m(); raise SystemExit(1)\n")
        with tarfile.open(os.path.join(target, "canary-1.0.tar.gz"), "w:gz") as t:
            t.add(pkg, arcname="canary-1.0")
        with open(os.path.join(target, "requirements.txt"), "w") as f:
            f.write("./canary-1.0.tar.gz\nrequests==2.0.0\n")
        sc = PipAuditScanner(target)
        try:
            asyncio.run(sc.scan())
            text = " ".join(sc.warnings)
        except Exception as e:  # noqa: BLE001 — advisory service is unreachable offline
            text = str(e)
        if os.path.exists(marker) or "isolated environment" in text or "Failed to upgrade" in text:
            raise RuntimeError("pip-audit acted on a target-supplied package")
        return 1, ""
    finally:
        shutil.rmtree(td, ignore_errors=True)


def build_checks(root: str) -> List[Tuple[str, Callable[[], Tuple[int, str]], int]]:
    from scanner.scanners.iac import CheckovScanner, HadolintScanner, TrivyIaCScanner
    from scanner.scanners.sast import BanditScanner
    from scanner.scanners.secrets import DetectSecretsScanner, GitleaksScanner

    p = lambda *a: os.path.join(root, *a)  # noqa: E731
    return [
        ("semgrep", lambda: _semgrep(root), 1),
        ("bandit", lambda: (_count(BanditScanner, p("vulnerable")), ""), 2),
        ("checkov", lambda: (_count(CheckovScanner, p("smoke", "iac")), ""), 1),
        ("hadolint", lambda: (_count(HadolintScanner, p("smoke", "docker")), ""), 1),
        ("gitleaks", lambda: (_count(GitleaksScanner, p("smoke", "secrets")), ""), 1),
        ("detect-secrets", lambda: (_count(DetectSecretsScanner, p("smoke", "secrets")), ""), 1),
        ("trivy-iac", lambda: (_count(TrivyIaCScanner, p("smoke", "iac")), ""), 1),
        # Chỉ kiểm chạy được: trivy SCA / pip-audit / grype cần tải DB/advisory → không chạy offline.
        ("trivy --version", lambda: (_version("trivy", "--version"), ""), 1),
        ("grype version", lambda: (_version("grype", "version"), ""), 1),
        ("pip-audit-isolation", _pip_audit_isolation, 1),
        ("pip-audit --version", lambda: (_version("pip-audit", "--version"), ""), 1),
        ("semgrep --version", lambda: (_version("semgrep", "--version"), ""), 1),
    ]


def run(root: str, xfail: set) -> int:
    tmp = tempfile.mkdtemp(prefix="vg-scanner-smoke-")
    try:
        work = os.path.join(tmp, "fx")
        for sub in ("semgrep_rules", "vulnerable", "smoke"):
            shutil.copytree(os.path.join(root, sub), os.path.join(work, sub))
        rows: List[Result] = []
        failed = False
        for name, fn, minimum in build_checks(work):
            try:
                n, extra = fn()
                ok, detail = n >= minimum, f"{n} findings (cần ≥{minimum}) {extra}".strip()
            except Exception as e:  # noqa: BLE001 — mọi lỗi đều là kết quả check
                ok, detail = False, f"{type(e).__name__}: {str(e)[-300:]}"
            if ok:
                status = "XPASS" if name in xfail else "ok"
            elif name in xfail:
                status = "XFAIL"
            else:
                status, failed = "FAIL", True
            rows.append((name, status, detail))
        width = max(len(r[0]) for r in rows)
        print("Scanner smoke:")
        for name, status, detail in rows:
            print(f"  {name:<{width}}  {status:<5}  {detail}")
        if any(r[1] == "XPASS" for r in rows):
            print("NOTE: check XPASS → bỏ khỏi --xfail (đã sửa xong).")
        if failed:
            print("FAIL: scanner trên hỏng/không tìm ra lỗi đã biết trong image.")
        return 1 if failed else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: List[str]) -> int:
    args = argv[1:]
    xfail: set = set()
    if "--xfail" in args:
        i = args.index("--xfail")
        xfail = {x for x in args[i + 1].split(",") if x} if i + 1 < len(args) else set()
        del args[i:i + 2]
    if len(args) != 1 or not os.path.isdir(args[0]):
        print("usage: python -m scanner.scanners.selftest <tests/fixtures> [--xfail a,b]", file=sys.stderr)
        return 2
    return run(args[0], xfail)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
