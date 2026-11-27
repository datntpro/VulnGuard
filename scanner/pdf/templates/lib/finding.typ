#import "theme.typ": *

// A detailed finding card. All strings are VALUES from the data document.
#let finding-card(d, f) = {
  let sev = f.at("severity", default: "INFO")
  let (c, b) = sev-pair(sev)
  let badge = f.at("badge", default: "")
  let vec = f.at("vector", default: "")
  let code = f.at("code", default: "")
  let ev = f.at("evidence", default: "")
  block(stroke: (left: 3pt + c, rest: 0.5pt + line-c), radius: 3pt, width: 100%, breakable: true, below: 9pt)[
    #block(fill: b, inset: (x: 8pt, y: 6pt), width: 100%, sticky: true, below: 0pt)[
      #grid(columns: (auto, 1fr), gutter: 6pt, align: horizon,
        stack(spacing: 3pt, sev-pill(d, sev),
          if badge != "" { text(size: 5.8pt, weight: "bold", fill: rgb("#15803d"), tracking: 0.3pt, badge) }),
        heading(level: 2, outlined: true, bookmarked: true,
          f.at("id", default: "") + " · " + f.at("title_short", default: f.at("title", default: ""))))
    ]
    #let cells = f.at("meta", default: ())
    #if cells.len() > 0 {
      block(inset: 0pt, width: 100%, sticky: true, below: 0pt, breakable: false,
        table(columns: (1fr,) * cells.len(),
          stroke: (x, y) => (bottom: 0.5pt + line-c, right: if x < cells.len() - 1 { 0.5pt + line-c }), inset: 5pt,
          ..cells.map(kv => [#text(size: 6.2pt, fill: muted, weight: "semibold", tracking: 0.6pt, upper(kv.at(0))) \
            #text(size: 8pt, kv.at(1))])))
    }
    #block(inset: 8pt, width: 100%)[
      #set text(size: 8.8pt)
      #if f.at("title_short", default: "") != f.at("title", default: "") [
        #text(weight: "semibold")[#f.at("title", default: "")]
      ]
      #if vec != "" [
        #lbl(lab(d, "vector"))
        #raw(vec)
      ]
      #if f.at("description", default: "") != "" [
        #lbl(lab(d, "description"))
        #f.at("description")
      ]
      #if f.at("location", default: "") != "" [
        #lbl(lab(d, "location"))
        #raw(f.at("location"))
      ]
      #if code != "" [
        #lbl(lab(d, "code"))
        #code-box(code)
      ]
      #if ev != "" [
        #lbl(lab(d, "evidence"))
        #code-box(ev)
      ]
      #for x in f.at("extra", default: ()) [
        #lbl(x.at("label", default: ""))
        #if x.at("mono", default: false) { code-box(x.at("body", default: "")) } else [#x.at("body", default: "")]
      ]
      #if f.at("remediation", default: "") != "" [
        #lbl(lab(d, "remediation"))
        #f.at("remediation")
      ]
      #if f.at("refs", default: ()).len() > 0 [
        #v(2pt)
        #text(size: 7.6pt, fill: rgb("#334155"))[#f.at("refs").join("   ")]
      ]
    ]
  ]
}

#let detail-section(d) = {
  let fs = d.at("findings", default: ()).filter(f => f.at("detail", default: false))
  heading(level: 1, lab(d, "details"))
  if fs.len() == 0 { text(fill: muted, lab(d, "no_details")) }
  for f in fs { finding-card(d, f) }
}
