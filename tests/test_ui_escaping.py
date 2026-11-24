"""Static regression tests: no unescaped data in innerHTML sinks (PR-D)."""
import re
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web"
INDEX = (WEB / "index.html").read_text(encoding="utf-8")
AGENT = (WEB / "agent.html").read_text(encoding="utf-8")


def test_index_no_raw_error_message():
    assert not re.findall(r"\$\{\s*e\.message\s*\}", INDEX)


def test_agent_no_raw_error_message():
    assert not re.findall(r"\$\{\s*e\.message\s*\}", AGENT)


def test_index_sinks_are_escaped():
    pat = re.compile(r"\$\{\s*(result\.message|v\.title|f\.label|f\.path|f\.id|m\.name"
                     r"|summary\.approve_message|v\.priority_reason|v\.severity_original)\s*(\}|\.slice|\|\|)")
    assert not pat.findall(INDEX)


def test_deletemodel_uses_jsstr():
    assert "deleteModel('${m.name}')" not in INDEX
    assert "deleteModel('${jsStr(m.name)}')" in INDEX


def test_agent_esc_escapes_quotes():
    m = re.search(r"function esc\(s\)[^\n]*", AGENT)
    assert m and "&quot;" in m.group(0) and "&#39;" in m.group(0)
