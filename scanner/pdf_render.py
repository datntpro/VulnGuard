"""
Render HTML → PDF phía server bằng headless Chromium (nếu có).

Thứ tự thử: Playwright chromium → binary chrome/chromium hệ thống. Nếu không có
trình duyệt, raise PdfUnavailable để API trả hướng dẫn (dùng nút "Lưu PDF / In").
KHÔNG thêm dependency bắt buộc — chỉ dùng khi môi trường đã có trình duyệt.
"""
import os
import shutil
import subprocess
import tempfile

_PDF_MARGIN = {"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"}


class PdfUnavailable(RuntimeError):
    """Không có trình duyệt headless để render PDF."""


def _via_playwright(html: str) -> bytes:
    from playwright.sync_api import sync_playwright
    kwargs = {"args": ["--no-sandbox", "--disable-dev-shm-usage"]}
    exe = os.environ.get("CHROMIUM_PATH") or "/opt/pw-browsers/chromium"
    if os.path.exists(exe):
        kwargs["executable_path"] = exe
    with sync_playwright() as p:
        browser = p.chromium.launch(**kwargs)
        try:
            page = browser.new_page()
            page.set_content(html, wait_until="load")
            return page.pdf(format="A4", print_background=True, margin=_PDF_MARGIN)
        finally:
            browser.close()


def _find_chrome() -> str:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    for p in ("/opt/pw-browsers/chromium", "/usr/bin/chromium", "/usr/bin/google-chrome"):
        if os.path.exists(p):
            return p
    return ""


def _via_chrome_binary(html: str) -> bytes:
    chrome = _find_chrome()
    if not chrome:
        raise PdfUnavailable("Không tìm thấy Chromium/Chrome")
    d = tempfile.mkdtemp(prefix="vg-pdf-")
    html_path = os.path.join(d, "r.html")
    pdf_path = os.path.join(d, "r.pdf")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    cmd = [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
           "--disable-dev-shm-usage", "--no-pdf-header-footer",
           f"--print-to-pdf={pdf_path}", "file://" + html_path]
    try:
        subprocess.run(cmd, capture_output=True, timeout=90, check=False)  # noqa: S603
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            with open(pdf_path, "rb") as f:
                return f.read()
        # một số bản cần cờ cũ
        cmd[1] = "--headless"
        subprocess.run(cmd, capture_output=True, timeout=90, check=False)  # noqa: S603
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            with open(pdf_path, "rb") as f:
                return f.read()
        raise PdfUnavailable("Chrome không xuất được PDF")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def html_to_pdf(html: str) -> bytes:
    """Trả bytes PDF. Raise PdfUnavailable nếu không có trình duyệt headless."""
    try:
        return _via_playwright(html)
    except PdfUnavailable:
        raise
    except Exception:
        return _via_chrome_binary(html)
