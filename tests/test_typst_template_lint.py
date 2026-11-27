"""Template/Python lint (plan §6): no eval, no packages, no data-derived file/URL sinks,
and Python never builds .typ source."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "scanner" / "pdf" / "templates"
PYDIR = ROOT / "scanner" / "pdf"

ALLOWED_CALLS = (
    'json(bytes(sys.inputs.at("data")))',
    'image(bytes(sys.inputs.at("chart_svg")), format: "svg")',
)
FILE_FUNCS = r"read|image|json|csv|yaml|toml|xml|cbor|plugin|bibliography"


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)(?<!:)//.*$", "", src)


_LITERAL_CALL = re.compile(rf"(?<![\w.-])(?:{FILE_FUNCS})\s*\(\s*\"[^\"\\]*\"\s*[,)]")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
# identifiers that must never appear anywhere (aliasing / method / field access included)
_NEVER = re.compile(r"(?<![\w-])(eval|plugin|std|read|image|json|csv|yaml|toml|xml|cbor|bibliography)(?![\w-])")


def lint_typ(src: str) -> list[str]:
    s = _strip_comments(src)
    s0 = s
    bad: list[str] = []
    if re.search(r"\b(import|include)\s+\"@", s):
        bad.append("package import/include")
    if re.search(r"\b(import|include)\s+(?!\")", s):
        bad.append("non-literal import/include")
    # blank out the sanctioned call forms, then mask every remaining string literal
    for a in ALLOWED_CALLS:
        s = s.replace(a, "__OK__")
    s = _LITERAL_CALL.sub("__OK__(", s)
    s = _STRING.sub('""', s)
    for m in _NEVER.finditer(s):
        bad.append(f"forbidden identifier {m.group(1)!r} (aliases/field access included)")
    for fn in ("link", "label", "ref", "cite"):
        if re.search(rf"(?<![\w-]){fn}\s*\(", s):
            bad.append(f"{fn}(")
    if re.search(r"\braw\s*\([^)]*\blang\s*:\s*[^\"\s]", s):
        bad.append("raw(lang: <data>)")
    for m in re.finditer(r"sys\.inputs\S*", s0):
        if not re.match(r'sys\.inputs\.at\("(data|chart_svg)"\)', s0[m.start():]):
            bad.append("sys.inputs use outside data/chart_svg")
    return bad


def _templates():
    return sorted(TEMPLATES.rglob("*.typ"))


@pytest.mark.parametrize("path", _templates(), ids=lambda p: p.relative_to(TEMPLATES).as_posix())
def test_shipped_templates_are_clean(path):
    assert lint_typ(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "src",
    [
        '#eval(sys.inputs.at("data"))',
        '#import "@preview/x:1.0.0": *',
        '#include "@local/x:1.0.0"',
        '#let p = d.path\n#read(p)',
        '#image(d.logo)',
        '#json(sys.inputs.at("x"))',
        '#link(d.url)[x]',
        '#label(d.id)',
        '#raw(d.code, lang: d.lang)',
        '#csv("/etc/passwd")x#read(sys.inputs.at("data"))',
        '#import d.mod',
        '#let r = read\n#r(d.p)',
        '#let e = eval\n#e(d.t, mode: "markup")',
        '#(read)(d.p)',
        '#let r = read\n#r.with(encoding: none)(d.p)',
        '#let p = plugin\n#p(d.w)',
        '#let r = std.read',
        '#let x = (a: image)\n#(x.a)(d.p)',
        '#let j = json\n#j(d.p)',
        '#let c = csv\n#c(d.p)',
        '#let y = yaml\n#let x = xml\n#let t = toml\n#let b = cbor',
        '#{ let f = read; f(d.p) }',
        '#import d.mod: read',
        '#include d.p',
    ],
)
def test_lint_catches_bad_patterns(src):
    assert lint_typ(src), src


def test_lint_allows_the_two_sanctioned_calls_and_literals():
    ok = '#let d = json(bytes(sys.inputs.at("data")))\n#image(bytes(sys.inputs.at("chart_svg")), format: "svg")\n#image("assets/logo.png")\n// eval( in a comment'
    assert lint_typ(ok) == []


def test_python_never_builds_typst_source():
    """engine passes only a *path* to our template; no f-string/format/concat produces Typst."""
    for py in PYDIR.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        # typst.compile only in the worker, and only fed os.path.join(root, entry)
        if py.name != "worker.py":
            assert "typst.compile" not in text, py.name
        assert not re.search(r"""\.encode\(\)\s*,\s*root=""", text)
        for m in re.finditer(r"""f["'][^"'\n]*(#let|#set|#import|#read|#show|#image)""", text):
            pytest.fail(f"{py.name}: f-string builds Typst markup: {m.group(0)}")
    worker = (PYDIR / "worker.py").read_text(encoding="utf-8")
    assert "os.path.join(root, entry)" in worker
    assert "eval(" not in worker.replace("typst", "")  # no python eval either
