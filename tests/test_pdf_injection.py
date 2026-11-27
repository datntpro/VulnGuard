"""Injection corpus: scan strings are *values* in sys.inputs and must render literally,
never execute, never read files (plan §5 F9/F10, §6)."""
import json

import pytest

from scanner.pdf import engine
from scanner.pdf.sanitize import clean_text
from tests._pdf_helpers import compile_src, data_inputs, norm, pdf_text

CORPUS = [
    '#import "@preview/tablex:0.0.9": tablex',
    '#include "report.typ"',
    '#read("/etc/hosts")',
    '#read("report.typ")',
    '#read("../outside.txt")',
    '#image("fonts/DejaVuSans.ttf")',
    '#plugin("x.wasm")',
    '#eval("1+1")',
    '#show: x => "PWNED-SHOW"',
    '#set page(width: 1pt) #eval("1+1")',
    "] #text(red)[PWNED-BRACKET] [",
    "*bold* _emph_ $x^2$ = Heading <lbl> @lbl // comment /* open",
    '```typ\n#panic("PWNED-RAW")\n```',
    '\\u{41} \\ #"str" #{ panic("x") }',
    "Đối tượng Ưu Ơn ỹ ặ ẫ",
    "RTL \u202e override, NUL \u0000, BOM \ufeff end",
    "A" * 3000,
]

FIELDS = ("title", "description", "code", "evidence")


def _doc(canary_path: str):
    items = CORPUS + [f'#read("{canary_path}")', f'#image("{canary_path}")']
    return {"title": "Injection", "findings": [{**{f: t for f in FIELDS}, "severity": "HIGH"} for t in items]}


def test_corpus_renders_literally_in_every_field(tmp_path):
    canary = tmp_path / "secret.txt"
    canary.write_text("SECRET-OUTSIDE-CANARY")
    pdf = engine.render("scan", _doc(str(canary)), generated_at=0)
    text = pdf_text(pdf)
    n = norm(text)
    for item in CORPUS + [f'#read("{canary}")']:
        expect = norm(clean_text(item, wrap=False))
        # 3000-char token: just check a long prefix (wrap points + page breaks only add whitespace)
        assert expect[:200] in n, f"not literal: {item[:40]!r}"
    # markers that only appear if something executed / read a file
    assert "SECRET-OUTSIDE-CANARY" not in text
    assert "localhost" not in text and "127.0.0.1" not in text  # /etc/hosts content
    assert "sys.inputs" not in text  # template source (read("report.typ")) not leaked
    # executed #show would have replaced content wholesale; the literal marker count proves it did not
    assert text.count("PWNED-SHOW") >= len(FIELDS)


def test_sanitizer_strips_controls_and_bidi():
    s = clean_text("a\u202eb\u0000c\ufeffd\u2066e")
    assert s == "abcde"
    assert clean_text("x" * 130, wrap=True).count("\u200b") == 2


def test_negative_control_splice_and_eval_would_leak(tmp_path):
    """Proves the harness is sensitive: eval()/splicing of the same payload DOES leak.
    This is why eval/splice are banned (lint) -- never copy this pattern."""
    src = '#eval(sys.inputs.at("t"), mode: "markup")'
    pdf = compile_src(
        src, {"t": '#read("inroot.typ")'}, extra={"inroot.typ": b"IN-ROOT-FILE-CONTENT"}
    )
    assert "IN-ROOT-FILE-CONTENT" in pdf_text(pdf)


@pytest.mark.parametrize("item", CORPUS[:8])
def test_value_channel_never_leaks_in_root_file(item):
    src = '#let d = json(bytes(sys.inputs.at("data")))\n#d.t'
    pdf = compile_src(src, data_inputs({"t": item}), extra={"inroot.typ": b"IN-ROOT-FILE-CONTENT"})
    assert "IN-ROOT-FILE-CONTENT" not in pdf_text(pdf)


def test_adapter_fields_render_literally_end_to_end(tmp_path):
    """Hostile strings in every adapter-fed field (scan, pentest, webscan) stay literal text."""
    from types import SimpleNamespace as NS

    from scanner.pdf import adapters
    from tests._pdf_fixtures import NOW, make_pentest_model, make_scan
    from tests._pdf_helpers import norm, pdf_text

    canary = tmp_path / "secret.txt"
    canary.write_text("SECRET-OUTSIDE-CANARY")
    evil = f'#read("{canary}") #image("{canary}") #eval("1+1") ] #show: x => "PWNED" ['
    p, s, g, c = make_scan(4, hostile=True)
    p.name = evil
    for grp in g.values():
        for gg in grp:
            gg["items"][0]["file_path"] = evil
            gg["items"][0]["code_snippet"] = evil
            gg["ai_fix_suggestion"] = evil
    pdf = engine.render("scan", adapters.scan_doc(p, s, g, c, now=NOW, branding={"org_name": evil}), generated_at=0)
    t = pdf_text(pdf)
    assert "SECRET-OUTSIDE-CANARY" not in t and "localhost" not in t
    assert norm('#eval("1+1")') in norm(t)
    m = make_pentest_model()
    m["findings"][0]["title"] = evil
    m["findings"][0]["evidence_traffic"]["request_body"] = evil
    m["run"]["engagement"] = evil
    t = pdf_text(engine.render("pentest", adapters.pentest_doc(m), generated_at=0))
    assert "SECRET-OUTSIDE-CANARY" not in t and norm('#eval("1+1")') in norm(t)
    scan = NS(id="x", started_at=None, status=None, authorized_by=evil)
    fs = [{"name": evil, "severity": "high", "matched_at": evil, "description": evil, "remediation": evil,
           "curl_command": evil, "reference": [evil], "extracted": [evil]}]
    t = pdf_text(engine.render("webscan", adapters.webscan_doc(scan, fs), generated_at=0))
    assert "SECRET-OUTSIDE-CANARY" not in t and norm('#eval("1+1")') in norm(t)
