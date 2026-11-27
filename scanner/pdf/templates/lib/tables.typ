#import "theme.typ": *

#let low-section(d) = {
  let fs = d.at("findings", default: ()).filter(f => not f.at("detail", default: false))
  heading(level: 1, lab(d, "low_info"))
  text(fill: muted, lab(d, "low_info_note"))
  if d.at("truncated_note", default: "") != "" { par(text(fill: danger, d.at("truncated_note"))) }
  if fs.len() == 0 { par(text(fill: muted, lab(d, "none_low"))) } else {
    table(columns: (15mm, 24mm, 1fr, 50mm, 20mm), stroke: (x, y) => (bottom: 0.5pt + line-c),
      fill: (x, y) => if y == 0 { brand } else if calc.even(y) { rgb("#fbfcfe") }, inset: 4.5pt,
      table.header(..(lab(d, "col_id"), lab(d, "col_sev"), lab(d, "col_finding"), lab(d, "col_location"), lab(d, "col_cwe")).map(h =>
        text(fill: white, weight: "semibold", size: 7.8pt, h))),
      ..fs.map(f => (
        text(size: 7.4pt, f.at("id", default: "")),
        sev-pill(d, f.at("severity", default: "INFO")),
        text(size: 8pt, f.at("title", default: "")),
        text(size: 7pt, raw(f.at("location", default: ""))),
        text(size: 8pt, f.at("cwe", default: "")))).flatten())
  }
}
