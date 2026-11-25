"""PR-H: Docker hardening + supply chain (N-5, N-9, L-5, B-6) — kiểm tra tĩnh trên file cấu hình.

Mỗi test tái hiện PoC của reverify: ``:ro`` docker.sock vẫn cho tạo container privileged,
``curl | sh`` không pin, dependency ``>=`` trôi phiên bản, v.v.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _code_lines(rel):
    """Dòng không phải comment."""
    return [ln for ln in _read(rel).splitlines() if not ln.strip().startswith("#")]


# ── N-5: docker.sock ──────────────────────────────────────────────
def test_default_compose_has_no_docker_socket():
    code = "\n".join(_code_lines("docker-compose.yml"))
    assert "docker.sock" not in code
    assert "DOCKER_SOCK" not in code


def test_local_images_override_uses_pinned_readonly_socket_proxy():
    text = _read("docker-compose.local-images.yml")
    code = "\n".join(_code_lines("docker-compose.local-images.yml"))
    assert re.search(r"image:\s*tecnativa/docker-socket-proxy:\S+@sha256:[0-9a-f]{64}", code)
    for flag in ("POST=0", "CONTAINERS=0", "EXEC=0", "BUILD=0", "IMAGES=1"):
        assert flag in code, flag
    assert "DOCKER_HOST=tcp://docker-socket-proxy:2375" in code
    assert "ports:" not in code, "proxy port must not be published"
    assert "read_only: true" in code and "no-new-privileges:true" in code
    # app không được mount socket trong override
    app_block = text.split("\n  vulnguard:")[1]
    assert "docker.sock" not in app_block


# ── N-9: storage ownership ────────────────────────────────────────
def test_compose_no_chmod_777_hint():
    assert "chmod -R 777" not in _read("docker-compose.yml")
    assert "chown -R 10001:10001 storage" in _read("docker-compose.yml")


def _run_entrypoint(storage: Path):
    env = dict(os.environ, VULNGUARD_STORAGE_DIR=str(storage))
    return subprocess.run(["sh", str(ROOT / "api/docker-entrypoint.sh"), "echo", "started"],
                          capture_output=True, text=True, env=env)


def test_entrypoint_ok_when_storage_writable(tmp_path):
    (tmp_path / "db").mkdir()
    r = _run_entrypoint(tmp_path)
    assert r.returncode == 0 and "started" in r.stdout


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root bỏ qua quyền ghi")
def test_entrypoint_explains_chown_when_storage_not_writable(tmp_path):
    db = tmp_path / "db"
    db.mkdir()
    db.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        r = _run_entrypoint(tmp_path)
    finally:
        db.chmod(stat.S_IRWXU)
    assert r.returncode == 1
    assert "chown -R 10001:10001 storage" in r.stderr
    assert "started" not in r.stdout


def test_entrypoint_is_wired_in_dockerfile():
    d = _read("api/Dockerfile")
    assert "docker-entrypoint.sh" in d and re.search(r"^ENTRYPOINT\s", d, re.M)
    assert os.access(ROOT / "api/docker-entrypoint.sh", os.X_OK)


# ── L-5: binaries ─────────────────────────────────────────────────
def _dockerfile_run_blocks():
    """Gộp các dòng nối bằng '\\' thành từng lệnh RUN."""
    text = _read("api/Dockerfile")
    blocks, cur = [], None
    for ln in text.splitlines():
        if cur is None and ln.startswith("RUN "):
            cur = ln
        elif cur is not None:
            cur += "\n" + ln
        else:
            continue
        if not ln.rstrip().endswith("\\"):
            blocks.append(cur)
            cur = None
    return blocks


def test_no_pipe_to_shell_installers():
    for b in _dockerfile_run_blocks():
        assert not re.search(r"\|\s*(sh|bash)\b", b), b[:200]
    assert "install.sh" not in "\n".join(_code_lines("api/Dockerfile"))


def test_every_downloaded_binary_is_checksummed():
    for b in _dockerfile_run_blocks():
        if re.search(r"\bcurl\b", b) and "http" in b:
            assert "sha256sum -c" in b, f"binary không kiểm sha256:\n{b[:300]}"


@pytest.mark.parametrize("tool", ["trivy", "gitleaks", "grype", "hadolint", "katana", "nuclei", "ffuf", "sonar"])
def test_per_arch_sha256_args(tool):
    d = _read("api/Dockerfile")
    for arch in ("AMD64", "ARM64"):
        m = re.search(rf"^ARG {tool.upper()}_SHA256_{arch}=([0-9a-f]{{64}})$", d, re.M)
        assert m, f"{tool} thiếu ARG sha256 {arch}"


def test_core_scanners_fail_the_build():
    for b in _dockerfile_run_blocks():
        if any(f"/{t}" in b or f"{t}.tgz" in b for t in ("trivy", "gitleaks", "grype", "hadolint")) and "curl" in b:
            assert "|| echo" not in b, b[:200]
            assert "set -eu" in b, b[:200]


def test_trivy_not_from_unpinned_apt():
    code = "\n".join(_code_lines("api/Dockerfile"))
    assert "apt-get install -y trivy" not in code
    assert "trivy-repo" not in code


def test_seclists_pinned_to_tag():
    d = _read("api/Dockerfile")
    m = re.search(r"git clone[^\n]*SecLists", d)
    assert m and "--branch" in m.group(0)


def test_no_floating_version_defaults():
    d = _read("api/Dockerfile")
    assert "NUCLEI_VERSION=" in d and re.search(r"ARG GRYPE_VERSION=\d", d)


# ── B-6: lockfiles ────────────────────────────────────────────────
def _lock_entries(rel):
    """[(name, version, has_hash)] từ lockfile pip-compile."""
    entries, cur = [], None
    for ln in _read(rel).splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]+\])?==([^\s;\\]+)", ln)
        if m:
            cur = [m.group(1).lower(), m.group(3), False]
            entries.append(cur)
        elif cur and "--hash=sha256:" in ln:
            cur[2] = True
    return entries


def test_app_requirements_is_hash_locked():
    entries = _lock_entries("api/requirements.txt")
    assert len(entries) > 30
    assert all(h for _, _, h in entries), [n for n, _, h in entries if not h]
    code = [ln for ln in _code_lines("api/requirements.txt") if ln.strip()]
    assert not any(">=" in ln or "<" in ln.split(";")[0] for ln in code if "==" not in ln and not ln.strip().startswith(("--", "#")))


def test_requirements_in_is_source_and_has_detect_secrets():
    src = _read("api/requirements.in")
    assert "fastapi" in src and "detect-secrets" in src
    assert "detect-secrets" in {n for n, _, _ in _lock_entries("api/requirements.txt")}


def test_scanner_clis_not_in_app_environment():
    names = {n for n, _, _ in _lock_entries("api/requirements.txt")}
    for tool in ("bandit", "checkov", "pip-audit", "semgrep"):
        assert tool not in names, f"{tool} phải ở venv riêng (docker/scanners/)"


@pytest.mark.parametrize("tool", ["bandit", "checkov", "pip-audit", "semgrep"])
def test_scanner_venv_lock_present_and_hashed(tool):
    entries = _lock_entries(f"docker/scanners/{tool}.txt")
    assert any(n == tool for n, _, _ in entries)
    assert all(h for _, _, h in entries)


def test_dockerfile_installs_with_require_hashes_once():
    d = "\n".join(_code_lines("api/Dockerfile"))
    pips = re.findall(r"pip install[^\n]*", d)
    assert pips and all("--require-hashes" in p for p in pips), pips
    assert d.count("-r requirements.txt") == 1  # cài một lần (không "re-install")
    assert "Re-install" not in _read("api/Dockerfile")


def test_all_requirement_files_pinned():
    assert "--hash=sha256:" in _read("requirements-dev.txt")
    assert "--hash=sha256:" in _read("coworker_host/requirements.txt")
    dev = {n for n, _, _ in _lock_entries("requirements-dev.txt")}
    assert {"pytest", "bandit"} <= dev


def test_ci_installs_from_lock_and_audits():
    ci = _read(".github/workflows/ci.yml")
    assert "--require-hashes -r requirements-dev.txt" in ci
    assert "pip-audit" in ci and "api/requirements.txt" in ci


def test_dependabot_covers_pip_and_docker():
    d = _read(".github/dependabot.yml")
    assert "package-ecosystem: pip" in d and "package-ecosystem: docker" in d


def test_uvicorn_single_worker_and_forwarded_ips_in_image():
    d = _read("api/Dockerfile")
    assert "FORWARDED_ALLOW_IPS=127.0.0.1" in d
    assert '"--workers", "1"' in d


# ── Follow-ups từ verify PR #45 ───────────────────────────────────
def test_forwarded_allow_ips_reaches_container():  # F-1
    assert "FORWARDED_ALLOW_IPS=${FORWARDED_ALLOW_IPS:-127.0.0.1}" in _read("docker-compose.yml")


def test_defusedxml_in_lock():  # F-2: PR #43 phải bỏ dòng `defusedxml>=` thô trong requirements.txt
    assert "defusedxml" in _read("api/requirements.in")
    assert "defusedxml" in {n for n, _, _ in _lock_entries("api/requirements.txt")}
    assert "defusedxml" in {n for n, _, _ in _lock_entries("requirements-dev.txt")}


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root bỏ qua quyền ghi")
def test_entrypoint_detects_root_owned_db_file(tmp_path):  # F-3
    db = tmp_path / "db"
    db.mkdir()
    f = db / "vulnguard.db"
    f.write_text("x")
    f.chmod(stat.S_IRUSR)  # như file thuộc root còn lại sau khi nâng cấp
    try:
        r = _run_entrypoint(tmp_path)
    finally:
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert r.returncode == 1 and "chown -R 10001:10001 storage" in r.stderr


def test_entrypoint_derives_storage_from_database_url(tmp_path):  # F-3
    (tmp_path / "db").mkdir()
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{tmp_path}/db/vulnguard.db")
    env.pop("VULNGUARD_STORAGE_DIR", None)
    r = subprocess.run(["sh", str(ROOT / "api/docker-entrypoint.sh"), "echo", "ok"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "ok" in r.stdout


def test_native_installer_isolates_scanners():  # F-4
    sh = _read("install/install.sh")
    assert "--require-hashes -r \"$PROJECT_DIR/api/requirements.txt\"" in sh
    assert "docker/scanners/$tool.txt" in sh
    assert not re.search(r"pip\"? install[^\n]*\n?\s*semgrep", sh)
    assert "Re-install API packages" not in sh
