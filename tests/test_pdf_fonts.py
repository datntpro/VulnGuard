"""Only our bundled fonts get embedded; no Typst built-in/system fallback (plan §5 F13)."""
import io
import re

from pypdf import PdfReader

from scanner.pdf import engine

ALLOWED = re.compile(r"^(DejaVuSans(-Bold)?|DejaVuSansMono|BeVietnamPro-.*|JetBrainsMono-.*)$")


def _fonts(pdf):
    out = []
    for page in PdfReader(io.BytesIO(pdf)).pages:
        res = page["/Resources"]
        for f in (res.get("/Font") or {}).values():
            out.append(f.get_object())
    return out


def test_only_bundled_type0_truetype_fonts_embedded():
    pdf = engine.render(
        "scan",
        {"title": "Đối tượng kiểm thử", "findings": [{"title": "Ư Ơ ỹ ặ ẫ", "description": "d", "code": "=> != ->"}]},
        generated_at=0,
    )
    fonts = _fonts(pdf)
    assert fonts
    for f in fonts:
        assert f["/Subtype"] == "/Type0", f["/Subtype"]
        desc = f["/DescendantFonts"][0].get_object()
        assert "/FontFile2" in desc["/FontDescriptor"].get_object()
        base = re.sub(r"^[A-Z]{6}\+", "", str(f["/BaseFont"]).lstrip("/"))
        assert ALLOWED.match(base), base
        assert "Libertinus" not in base and "NewCM" not in base
