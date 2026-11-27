"""Server-generated charts. The SVG is built from integers and constants only: no user text ever
reaches it (the engine additionally rejects image/href/url()/script in the SVG)."""
from __future__ import annotations

import math
from typing import Mapping

SEV_COLORS = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#15803d", "INFO": "#94a3b8"}
_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def severity_donut(counts: Mapping[str, int], center_label: str = "") -> str:
    """Donut of per-severity counts. ``center_label`` must be a trusted constant (labels table)."""
    vals = {k: max(0, int(counts.get(k, 0) or 0)) for k in _ORDER}
    total = sum(vals.values())
    r = 42.0
    arcs = []
    nz = [k for k in _ORDER if vals[k]]
    if total == 0:
        arcs.append(f'<circle r="{r:g}" cx="60" cy="60" fill="none" stroke="#e2e8f0" stroke-width="18"/>')
    elif len(nz) == 1:
        arcs.append(f'<circle r="{r:g}" cx="60" cy="60" fill="none" stroke="{SEV_COLORS[nz[0]]}" stroke-width="18"/>')
    else:
        # Arc paths, not stroke-dasharray: Typst's SVG renderer ignores dash arrays (the approved
        # mockup rendered a single-colour ring because of that).
        ang = -math.pi / 2
        for k in nz:
            sweep = 2 * math.pi * vals[k] / total
            x0, y0 = 60 + r * math.cos(ang), 60 + r * math.sin(ang)
            x1, y1 = 60 + r * math.cos(ang + sweep), 60 + r * math.sin(ang + sweep)
            large = 1 if sweep > math.pi else 0
            arcs.append(
                f'<path d="M {x0:.3f} {y0:.3f} A {r:g} {r:g} 0 {large} 1 {x1:.3f} {y1:.3f}" '
                f'fill="none" stroke="{SEV_COLORS[k]}" stroke-width="18"/>'
            )
            ang += sweep
    safe_label = "".join(c for c in center_label if c.isalnum() or c in " ")  # defence in depth
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="160" height="160" viewBox="0 0 120 120">'
        + "".join(arcs)
        + f'<text x="60" y="62" text-anchor="middle" font-size="20" font-weight="800" fill="#0f172a">{total}</text>'
        + f'<text x="60" y="75" text-anchor="middle" font-size="7" fill="#64748b">{safe_label}</text></svg>'
    )
