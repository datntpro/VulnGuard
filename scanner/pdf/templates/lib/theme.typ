// Theme: colours, severity helpers, small components. No data access here beyond arguments.
#let brand = rgb("#1e3a5f")
#let accent = rgb("#d97706")
#let muted = rgb("#64748b")
#let line-c = rgb("#e2e8f0")
#let ink = rgb("#0f172a")
#let danger = rgb("#b91c1c")
#let sev-c = (
  CRITICAL: (rgb("#b91c1c"), rgb("#fef2f2")),
  HIGH: (rgb("#c2410c"), rgb("#fff7ed")),
  MEDIUM: (rgb("#a16207"), rgb("#fefce8")),
  LOW: (rgb("#15803d"), rgb("#f0fdf4")),
  INFO: (rgb("#475569"), rgb("#f1f5f9")),
)
#let sev-order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
#let sev-pair(s) = sev-c.at(upper(s), default: sev-c.at("INFO"))

// Localised label lookups (all prose lives in scanner/pdf/labels.py)
#let lab(d, key) = d.at("labels").at(key, default: "")
#let sev-name(d, s) = d.at("labels").at("sev").at(upper(s), default: s)

#let lbl(t) = block(above: 8pt, below: 3pt, sticky: true,
  text(size: 6.6pt, fill: muted, weight: "semibold", tracking: 0.8pt, t))

#let sev-pill(d, s) = {
  let (c, b) = sev-pair(s)
  box(fill: b, stroke: 0.6pt + c, inset: (x: 4pt, y: 2pt), radius: 2pt,
    text(fill: c, size: 6.8pt, weight: "bold", tracking: 0.3pt, upper(sev-name(d, s))))
}

// Dark code block. `body` is a string VALUE rendered through raw(); never markup.
#let code-box(body) = block(fill: ink, inset: 7pt, radius: 3pt, width: 100%, breakable: true,
  text(fill: rgb("#e2e8f0"), raw(body, block: true)))
