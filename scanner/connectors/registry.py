"""Registry connector + factory từ ConnectorConfig (giải mã secret)."""
from typing import Dict, Type

from scanner.connectors.base import BaseConnector
from scanner.connectors.fortinac import FortiNACConnector
from scanner.connectors.trellix import TrellixConnector
from scanner.connectors.trendmicro import TrendMicroConnector

REGISTRY: Dict[str, Type[BaseConnector]] = {
    "TRELLIX_XDR": TrellixConnector,
    "TRENDMICRO_VISION_ONE": TrendMicroConnector,
    "FORTINAC": FortiNACConnector,
}


def describe() -> list:
    out = []
    for kind, cls in REGISTRY.items():
        out.append({"kind": kind, "secret_fields": cls.secret_fields,
                    "config_fields": cls.config_fields, "supports_isolate": cls.supports_isolate})
    return out


def build_connector(kind: str, base_url, config: dict, secrets: dict) -> BaseConnector:
    cls = REGISTRY.get(kind)
    if not cls:
        raise ValueError(f"Connector kind không hỗ trợ: {kind}")
    return cls(base_url, config, secrets)
