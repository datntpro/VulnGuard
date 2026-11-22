from scanner.connectors.fortinac import parse_host
from scanner.connectors.trellix import parse_detection, parse_device
from scanner.connectors.trendmicro import parse_alert, parse_endpoint


def test_trendmicro_endpoint():
    a = parse_endpoint({"endpointName": "WIN-01", "ip": ["10.0.0.5"], "osName": "Windows",
                        "endpointType": "server", "agentGuid": "g1"})
    assert a.hostname == "WIN-01" and a.ip == "10.0.0.5" and a.asset_type == "SERVER"


def test_trendmicro_alert_technique():
    al = parse_alert({"id": "WB1", "model": "Ransomware", "severity": "high",
                      "indicators": [{"techniqueIds": ["T1486"]}],
                      "impactScope": {"entities": [{"entityValue": {"name": "WIN-01"}}]}})
    assert al[0].technique == "T1486" and al[0].hostname == "WIN-01"


def test_trellix_device_and_detection():
    d = parse_device({"id": "1", "attributes": {"name": "SRV", "ipAddress": "10.0.0.9"}})
    assert d.hostname == "SRV" and d.edr_agent_present
    t = parse_detection({"id": "t1", "attributes": {"threatName": "CS", "severity": "s5"}})
    assert t.severity == "critical"


def test_fortinac_vlan_to_exposure():
    h = parse_host({"hostname": "ws", "ip": "10.0.5.7", "currentVlan": "dmz", "status": "connected"},
                   {"internet_vlans": ["dmz"]})
    assert h.exposure == "INTERNET" and h.nac_status == "connected"
