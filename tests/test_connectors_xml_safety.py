"""L-6: connector XML parsers must not expand entities or read local files."""
import ast
import pathlib

import pytest

from scanner.connectors import openvas, qualys

BILLION_LAUGHS = (
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa">'
    '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
    '<HOST_LIST_OUTPUT><HOST><IP>&c;</IP><DNS>&c;</DNS></HOST></HOST_LIST_OUTPUT>'
)
XXE = (
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<HOST_LIST_OUTPUT><HOST><IP>1.1.1.1</IP><DNS>&xxe;</DNS><OS>&xxe;</OS></HOST></HOST_LIST_OUTPUT>'
)
XXE_RESULTS = XXE.replace("HOST_LIST_OUTPUT", "get_results_response").replace("<HOST>", "<result><host>").replace(
    "</HOST>", "</host><name>&xxe;</name></result>")

PARSERS = [
    qualys.parse_hosts_xml, qualys.parse_detections_xml,
    openvas.parse_results_xml, openvas.parse_assets_xml,
]


@pytest.mark.parametrize("fn", PARSERS)
@pytest.mark.parametrize("payload", [BILLION_LAUGHS, XXE, XXE_RESULTS])
def test_malicious_xml_is_rejected_without_expansion(fn, payload):
    out = fn(payload)
    assert out == []
    assert "root:" not in repr(out) and "aaaaaaaaaa" not in repr(out)


def test_benign_xml_still_parses():
    xml = "<HOST_LIST_OUTPUT><HOST><ID>1</ID><IP>10.0.0.1</IP><DNS>a</DNS></HOST></HOST_LIST_OUTPUT>"
    assert qualys.parse_hosts_xml(xml)[0].ip == "10.0.0.1"


def test_connectors_do_not_import_stdlib_etree():
    root = pathlib.Path(__file__).resolve().parents[1] / "scanner" / "connectors"
    for p in root.glob("*.py"):
        for node in ast.walk(ast.parse(p.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not any(n.startswith("xml.etree") for n in names), p.name
