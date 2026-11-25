#!/usr/bin/env python3
"""
VulnGuard — trình cài đặt & chạy ĐA NỀN TẢNG (macOS · Linux · Windows).
Chỉ dùng thư viện chuẩn. Gọi qua setup.sh (mac/linux) hoặc setup.ps1 (windows),
hoặc trực tiếp:  python3 scripts/setup.py

  python3 scripts/setup.py                      # tương tác: chọn Docker/Native + công cụ
  python3 scripts/setup.py --tools sast,sca,web --no-run
  python3 scripts/setup.py --check              # kiểm tra công cụ đã cài
  python3 scripts/setup.py --docker             # dùng Docker Compose (mọi OS)
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
OSID = "windows" if IS_WIN else ("macOS" if IS_MAC else "linux")      # token ProjectDiscovery
FFUF_OS = "windows" if IS_WIN else ("macos" if IS_MAC else "linux")
m = platform.machine().lower()
ARCH = "arm64" if m in ("arm64", "aarch64") else "amd64"
EXE = ".exe" if IS_WIN else ""

# ── màu (tắt trên Windows cổ) ──
def _c(code, s):
    if IS_WIN and not os.environ.get("WT_SESSION"):
        return s
    return f"\033[{code}m{s}\033[0m"
def g(s): print(_c("32", s))
def y(s): print(_c("33", s))
def r(s): print(_c("31", s))
def hr(): print("─" * 60)

PY_V = {"katana": "1.5.0", "nuclei": "3.4.7", "ffuf": "2.1.0"}

GROUPS = [
    ("sast", "SAST — quét source code (semgrep*, bandit)"),
    ("sca", "SCA — quét thư viện/CVE (trivy, pip-audit)"),
    ("secrets", "Secrets — lộ khoá/mật khẩu (detect-secrets, gitleaks)"),
    ("iac", "IaC — Terraform/K8s/Dockerfile (checkov, hadolint)"),
    ("container", "Container — quét image (grype)"),
    ("web", "Web/DAST — crawl + quét web (katana, nuclei)"),
    ("pentest", "Pentest Agent — tấn công (nmap, ffuf, sqlmap)"),
    ("ai", "AI local (tuỳ chọn) — Ollama"),
    ("sonar", "SonarQube scanner CLI (SAST sâu — cần server Sonar)"),
]
ALL_TOOLS = ["semgrep", "bandit", "trivy", "pip-audit", "gitleaks", "detect-secrets",
             "checkov", "hadolint", "grype", "katana", "nuclei", "nmap", "ffuf", "sqlmap", "ollama", "sonar-scanner"]


def venv_python() -> str:
    sub = "Scripts" if IS_WIN else "bin"
    return str(ROOT / ".venv" / sub / ("python.exe" if IS_WIN else "python"))


def bin_dir() -> Path:
    if IS_WIN:
        d = Path(os.environ.get("LOCALAPPDATA", ROOT)) / "VulnGuard" / "bin"
    else:
        # 1.6: các lệnh cài (curl ... | sh -b <dir>) KHÔNG dùng sudo → nếu
        # /usr/local/bin không ghi trực tiếp được thì dùng ~/.local/bin cho chắc.
        d = Path("/usr/local/bin")
        if not os.access(d, os.W_OK):
            d = Path.home() / ".local" / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d


def has(tool) -> bool:
    return shutil.which(tool) is not None or shutil.which(tool + EXE) is not None


def run(cmd, **kw):
    return subprocess.run(cmd, **kw).returncode == 0


def pkg_mgr():
    for pm in ("brew", "apt-get", "dnf", "yum", "winget", "choco"):
        if shutil.which(pm):
            return pm
    return None


def sys_install(*pkgs) -> bool:
    pm = pkg_mgr()
    sudo = [] if (IS_WIN or os.geteuid() == 0) else (["sudo"] if shutil.which("sudo") else [])
    try:
        if pm == "brew":
            return run(["brew", "install", *pkgs], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if pm == "apt-get":
            return run([*sudo, "apt-get", "install", "-y", *pkgs], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if pm in ("dnf", "yum"):
            return run([*sudo, pm, "install", "-y", *pkgs], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if pm == "winget":
            return run(["winget", "install", "-e", "--silent", *pkgs], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if pm == "choco":
            return run(["choco", "install", "-y", *pkgs], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return False


def pip_install(*pkgs):
    ok = run([venv_python(), "-m", "pip", "install", "-q", *pkgs],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    g(f"  ✓ {' '.join(pkgs)}") if ok else y(f"  ⚠ pip {' '.join(pkgs)} lỗi")
    return ok


def download_bin(url, member, out_name):
    """Tải archive, rút 1 binary vào bin_dir. member có thể kèm .exe."""
    try:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            arc = tdp / "arc"
            urllib.request.urlretrieve(url, arc)
            target = tdp / (out_name + EXE)
            if url.endswith(".zip"):
                with zipfile.ZipFile(arc) as z:
                    name = next((n for n in z.namelist() if Path(n).name in (member, member + ".exe")), None)
                    if not name:
                        return False
                    with z.open(name) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
            elif url.endswith((".tar.gz", ".tgz")):
                with tarfile.open(arc) as t:
                    name = next((n for n in t.getnames() if Path(n).name in (member, member + ".exe")), None)
                    if not name:
                        return False
                    f = t.extractfile(name)
                    with open(target, "wb") as dst:
                        shutil.copyfileobj(f, dst)
            else:
                shutil.move(str(arc), str(target))
            dest = bin_dir() / (out_name + EXE)
            _place(target, dest)
            if not IS_WIN:
                os.chmod(dest, 0o755)
            return True
    except Exception:
        return False


def _place(src: Path, dest: Path):
    try:
        shutil.move(str(src), str(dest))
    except PermissionError:
        subprocess.run(["sudo", "mv", str(src), str(dest)], check=True)


def pd_url(tool):  # ProjectDiscovery (katana/nuclei) + ffuf
    v = PY_V[tool]
    if tool == "ffuf":
        ext = "zip" if IS_WIN else "tar.gz"
        return f"https://github.com/ffuf/ffuf/releases/download/v{v}/ffuf_{v}_{FFUF_OS}_{ARCH}.{ext}"
    return f"https://github.com/projectdiscovery/{tool}/releases/download/v{v}/{tool}_{v}_{OSID}_{ARCH}.zip"


def _install_sonar_scanner(url, version, platform_tag):
    """Giải nén toàn bộ SonarScanner CLI (kèm JRE) vào bin_dir/.. rồi link bin."""
    try:
        import tempfile as _t
        dest_root = bin_dir().parent / "sonar-scanner"
        dest_root.mkdir(parents=True, exist_ok=True)
        with _t.TemporaryDirectory() as td:
            arc = Path(td) / "s.zip"
            urllib.request.urlretrieve(url, arc)  # noqa
            with zipfile.ZipFile(arc) as z:
                root_abs = str(dest_root.resolve())
                for member in z.infolist():
                    target = (dest_root / member.filename).resolve()
                    # chống zip-slip: member phải nằm trong dest_root
                    if str(target) != root_abs and not str(target).startswith(root_abs + os.sep):
                        raise ValueError(f"Archive member thoát thư mục: {member.filename}")
                    z.extract(member, dest_root)
        inner = dest_root / f"sonar-scanner-{version}-{platform_tag}"
        launcher = inner / "bin" / ("sonar-scanner.bat" if IS_WIN else "sonar-scanner")
        if not launcher.exists():
            return False
        if not IS_WIN:
            os.chmod(launcher, 0o755)
            link = bin_dir() / "sonar-scanner"
            if link.exists() or link.is_symlink():
                link.unlink()
            link.symlink_to(launcher)
        else:
            # Windows: thêm thư mục bin vào PATH người dùng là trách nhiệm user; báo đường dẫn
            print(f"    (Windows: thêm vào PATH: {inner / 'bin'})")
        return True
    except Exception:
        return False


def install_group(key):
    if key == "sast":
        if IS_WIN:
            y("  ⚠ semgrep không chạy native trên Windows — dùng Docker/WSL cho SAST semgrep.")
        else:
            pip_install("semgrep")
        pip_install("bandit")
    elif key == "sca":
        pip_install("pip-audit")
        if not has("trivy"):
            if sys_install("trivy"):
                g("  ✓ trivy")
            elif not IS_WIN and run(["bash", "-c",
                 f"curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b {bin_dir()}"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
                g("  ✓ trivy")
            else:
                y("  ⚠ trivy — cài thủ công (github.com/aquasecurity/trivy)")
    elif key == "secrets":
        pip_install("detect-secrets")
        if not has("gitleaks"):
            y("  ⚠ gitleaks — tải binary tại github.com/gitleaks/gitleaks/releases") if not sys_install("gitleaks") else g("  ✓ gitleaks")
    elif key == "iac":
        pip_install("checkov")
        if not has("hadolint"):
            g("  ✓ hadolint") if sys_install("hadolint") else y("  ⚠ hadolint — github.com/hadolint/hadolint/releases")
    elif key == "container":
        if not has("grype"):
            if sys_install("grype"):
                g("  ✓ grype")
            elif not IS_WIN and run(["bash", "-c",
                 f"curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b {bin_dir()}"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
                g("  ✓ grype")
            else:
                y("  ⚠ grype — github.com/anchore/grype/releases")
    elif key == "web":
        for t in ("katana", "nuclei"):
            if has(t):
                continue
            g(f"  ✓ {t}") if download_bin(pd_url(t), t, t) else y(f"  ⚠ {t} — github.com/projectdiscovery/{t}/releases")
        if has("nuclei"):
            subprocess.run([shutil.which("nuclei") or "nuclei", "-update-templates", "-silent"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif key == "pentest":
        for t in ("nmap", "sqlmap"):
            if not has(t):
                g(f"  ✓ {t}") if sys_install(t) else y(f"  ⚠ {t} — cài qua {pkg_mgr() or 'trình quản lý gói'}" + (" / nmap.org" if t == "nmap" else ""))
        if not has("ffuf"):
            g("  ✓ ffuf") if (sys_install("ffuf") or download_bin(pd_url("ffuf"), "ffuf", "ffuf")) else y("  ⚠ ffuf — github.com/ffuf/ffuf/releases")
        if not IS_WIN and not IS_MAC and not Path("/usr/share/seclists").exists():
            run(["bash", "-c", "sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif key == "sonar":
        if has("sonar-scanner"):
            return
        if IS_MAC and pkg_mgr() == "brew":
            g("  ✓ sonar-scanner") if sys_install("sonar-scanner") else y("  ⚠ sonar-scanner — brew install sonar-scanner")
        else:
            v = "6.2.1.4610"
            sc_os = "windows" if IS_WIN else ("macosx" if IS_MAC else "linux")
            sc_arch = "aarch64" if ARCH == "arm64" else "x64"
            url = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-{v}-{sc_os}-{sc_arch}.zip"
            if _install_sonar_scanner(url, v, f"{sc_os}-{sc_arch}"):
                g("  ✓ sonar-scanner")
            else:
                y("  ⚠ sonar-scanner — tải tại docs.sonarsource.com/sonarqube/latest/analyzing-source-code/scanners/sonarscanner")
    elif key == "ai":
        if not has("ollama"):
            if IS_WIN or IS_MAC:
                y("  ⚠ Tải Ollama tại ollama.com/download (rồi: ollama pull llama3.2)")
            else:
                run(["bash", "-c", "curl -fsSL https://ollama.com/install.sh | sh"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                g("  ✓ ollama (nhớ: ollama pull llama3.2)") if has("ollama") else y("  ⚠ ollama — ollama.com")


def check_tools():
    hr(); g("Trạng thái công cụ:")
    for t in ALL_TOOLS:
        print(("  " + _c("32", "✓") + " " + t) if has(t) else ("  " + _c("31", "✗") + " " + t))
    hr()


def ensure_venv():
    if not Path(".venv").exists():
        g("Tạo virtualenv + cài API dependencies…")
        run([sys.executable, "-m", "venv", ".venv"])
        run([venv_python(), "-m", "pip", "install", "-q", "--upgrade", "pip"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok = run([venv_python(), "-m", "pip", "install", "-q", "-r", "api/requirements.txt"],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    g("✓ Python dependencies") if ok else y("⚠ Lỗi cài deps — chạy: " + venv_python() + " -m pip install -r api/requirements.txt")


def set_env():
    envfile = ROOT / ".env"
    if envfile.exists():
        for line in envfile.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    db = (ROOT / "storage" / "db" / "vulnguard.db").as_posix()
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{db}")
    os.environ.setdefault("AI_CONFIG_FILE", str(ROOT / "storage" / "ai_config.json"))
    os.environ.setdefault("AUTH_ENABLED", "true")
    os.environ.setdefault("APP_ENV", "production")
    os.environ.setdefault("DEPLOY_MODE", "native")
    (ROOT / "storage" / "db").mkdir(parents=True, exist_ok=True)


def bootstrap_admin(email, skip):
    if skip:
        return
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    subprocess.run([venv_python(), "-m", "scripts.bootstrap_admin", email], env=env)


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def resolve_bind_host(environ=None):
    """Host uvicorn sẽ bind (B-5/M-2). Mặc định loopback; từ chối mở ra ngoài khi AUTH_ENABLED=false."""
    env = os.environ if environ is None else environ
    host = (env.get("VULNGUARD_HOST") or "127.0.0.1").strip()
    auth_on = (env.get("AUTH_ENABLED") or "true").strip().lower() not in ("false", "0", "no", "off")
    if not auth_on and host not in _LOOPBACK_HOSTS:
        raise SystemExit(
            f"❌ AUTH_ENABLED=false không được phép khi VULNGUARD_HOST={host} (mở ra mạng không xác thực). "
            "Bật AUTH_ENABLED=true hoặc dùng VULNGUARD_HOST=127.0.0.1.")
    return host


def run_prod():
    port = os.environ.get("VULNGUARD_PORT", "8080")
    host = resolve_bind_host()
    hr(); g(f"  VulnGuard PRODUCTION: http://{host}:{port}")
    g("  Dùng email/mật khẩu ADMIN ở trên để đăng nhập. (Ctrl+C để dừng)"); hr()
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    os.execve(venv_python(), [venv_python(), "-m", "uvicorn", "api.main:app",
              "--host", host, "--port", port], env) if not IS_WIN else \
        subprocess.call([venv_python(), "-m", "uvicorn", "api.main:app", "--host", host, "--port", port], env=env)


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--mode", choices=["docker", "native"])
    ap.add_argument("--tools", default=None, help="vd: sast,sca,web,pentest  hoặc  all / none")
    ap.add_argument("--no-run", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--docker", action="store_true")
    ap.add_argument("--admin-email", default=None)
    ap.add_argument("--skip-admin", action="store_true")
    a = ap.parse_args()
    interactive = a.tools is None and a.mode is None and not a.docker

    if a.check:
        check_tools(); return

    g("🛡️  VulnGuard — Cài đặt"); hr()
    print(f"OS: {platform.system()} ({ARCH}) · Trình quản lý gói: {pkg_mgr() or 'không rõ'}")

    mode = "docker" if a.docker else a.mode
    if mode is None and interactive:
        print("\nChọn cách chạy:\n  1) Docker Compose (gọn nhất, chạy GIỐNG NHAU trên mọi OS)\n  2) Native (Python venv + tự chọn công cụ)")
        mode = "native" if input("Lựa chọn [1]: ").strip() == "2" else "docker"
    mode = mode or "docker"

    if mode == "docker":
        if not shutil.which("docker"):
            r("❌ Chưa có Docker. Cài Docker Desktop (mac/win) hoặc docker-ce (linux) rồi chạy lại."); sys.exit(1)
        if not (ROOT / ".env").exists() and (ROOT / ".env.example").exists():
            shutil.copy(".env.example", ".env"); y("Đã tạo .env — sửa SCAN_WORKSPACE trỏ thư mục source.")
        g("Build image (gồm toàn bộ scanner + nmap/nuclei/ffuf/sqlmap)…")
        if run(["docker", "compose", "build"]) and not a.no_run:
            run(["docker", "compose", "up", "-d"])
            g(f"✅ http://localhost:{os.environ.get('VULNGUARD_PORT','8080')} — tạo ADMIN ở trang đăng nhập.")
        return

    # ── Native ──
    if not shutil.which("python3") and not shutil.which("python"):
        r("❌ Cần Python 3.11+."); sys.exit(1)
    ensure_venv()

    tools = a.tools
    if tools is None and interactive:
        print("\nChọn nhóm công cụ cần cài (bỏ qua nếu chỉ xem UI / Document Review):")
        for i, (k, d) in enumerate(GROUPS, 1):
            print(f"  {i}) {d}")
        print("  a) Tất cả (trừ AI)   n) Không cài thêm")
        sel = input("Nhập số cách nhau bởi dấu cách (vd: 1 2 6 7), hoặc a/n [a]: ").strip() or "a"
        if sel == "n":
            tools = ""
        elif sel == "a":
            tools = "sast sca secrets iac container web pentest"
        else:
            picked = [GROUPS[int(x) - 1][0] for x in sel.replace(",", " ").split() if x.isdigit() and 1 <= int(x) <= len(GROUPS)]
            tools = " ".join(picked)
    tools = (tools or "").replace(",", " ")
    if tools.strip() == "all":
        tools = "sast sca secrets iac container web pentest"
    if tools.strip() == "none":
        tools = ""

    if tools.strip():
        hr()
        for k in tools.split():
            desc = dict(GROUPS).get(k, k)
            g(f"▶ {desc}")
            install_group(k)
        hr()

    set_env()   # mặc định storage ngay trong thư mục cài — chạy được ở bất kỳ đâu
    check_tools()

    email = a.admin_email or os.environ.get("ADMIN_EMAIL")
    if not email and interactive and not a.skip_admin:
        email = input("Email ADMIN [admin@vulnguard.local]: ").strip()
    email = email or "admin@vulnguard.local"
    g("Tạo tài khoản ADMIN (sinh mật khẩu ngẫu nhiên nếu chưa có)…")
    bootstrap_admin(email, a.skip_admin)

    if not a.no_run:
        run_prod()
    else:
        g("✅ Cài xong. Chạy app: python3 scripts/setup.py --mode native --no-run  (hoặc bash run.sh / .\\run.ps1)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
