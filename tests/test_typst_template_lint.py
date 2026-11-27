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


def lint_typ(src: str) -> list[str]:
    s = _strip_comments(src)
    bad: list[str] = []
    if re.search(r"\beval\s*\(", s):
        bad.append("eval(")
    if re.search(r"\b(import|include)\s+\"@", s):
        bad.append("package import/include")
    for m in re.finditer(r"\b(import|include)\s+(?!\")", s):
        bad.append("non-literal import/include")
    for m in re.finditer(rf"(?<![\w.-])({FILE_FUNCS})\s*\(", s):
        rest = s[m.start():]
        if any(rest.startswith(a) for a in ALLOWED_CALLS):
            continue
        if re.match(rf"({FILE_FUNCS})\s*\(\s*\"[^\"\\]*\"", rest):
            continue  # string literal naming a file we ship
        bad.append(f"{m.group(1)}( with non-literal argument")
    for fn in ("link", "label", "ref", "cite"):
        if re.search(rf"(?<![\w.-]){fn}\s*\(", s):
            bad.append(f"{fn}(")
    if re.search(r"\braw\s*\([^)]*\blang\s*:\s*[^\"\s]", s):
        bad.append("raw(lang: <data>)")
    for m in re.finditer(r"sys\.inputs\S*", s):
        if not re.match(r'sys\.inputs\.at\("(data|chart_svg)"\)', s[m.start():]):
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
