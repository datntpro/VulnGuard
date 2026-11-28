#import "theme.typ": *

// The ONLY image call in the template set (sanctioned form; SVG is generated server-side from integers).
#let chart-figure(d) = {
  let chart = image(bytes(sys.inputs.at("chart_svg")), format: "svg")
  figure(block(width: 56mm, chart), caption: lab(d, "severity_dist"), supplement: lab(d, "figure"))
}

#let summary-section(d) = {
  let sm = d.at("summary")
  let counts = sm.at("counts")
  let warning = sm.at("warning", default: "")
  if warning != "" {
    block(stroke: 1pt + accent, fill: rgb("#fffbeb"), inset: 8pt, radius: 3pt, width: 100%,
      text(fill: rgb("#92400e"), weight: "semibold", size: 8.5pt, str(warning)))
    v(4pt)
  }
  grid(columns: (1fr,) * 5, gutter: 5pt,
    ..sev-order.map(s => {
      let (c, b) = sev-pair(s)
      block(stroke: (top: 3pt + c, rest: 0.5pt + line-c), inset: 7pt, radius: 3pt, width: 100%)[
        #text(size: 17pt, weight: "extrabold", fill: c)[#str(counts.at(s, default: 0))] \
        #text(size: 6.6pt, fill: muted, weight: "semibold", tracking: 0.6pt)[#upper(sev-name(d, s))]]
    }))
  v(6pt)
  grid(columns: (58mm, 1fr), gutter: 9mm,
    chart-figure(d),
    [
      #text(weight: "bold")[#lab(d, "conclusion"):] #sm.at("narrative", default: "")
      #v(4pt)
      #if sm.at("priorities", default: ()).len() > 0 [
        #block(fill: rgb("#f8fafc"), stroke: 0.5pt + line-c, inset: 8pt, radius: 4pt, width: 100%)[
          *#lab(d, "priorities")*
          #for p in sm.at("priorities") [- #p]
        ]
      ]
    ])
  if sm.at("by_type", default: ()).len() > 0 {
    heading(level: 2, lab(d, "by_type"))
    table(columns: (1fr, 22mm, 30mm, 1fr), stroke: (x, y) => (bottom: 0.5pt + line-c),
      fill: (x, y) => if y == 0 { brand }, inset: 5pt,
      table.header(..(lab(d, "col_type"), lab(d, "col_count"), lab(d, "col_worst"), lab(d, "col_tools")).map(h =>
        text(fill: white, weight: "semibold", size: 8pt, h))),
      ..sm.at("by_type").map(r => (r.at("name", default: ""), str(r.at("count", default: 0)),
        sev-pill(d, r.at("worst", default: "INFO")), r.at("tools", default: ""))).flatten())
  }
  let ts = sm.at("tool_status", default: ())
  if ts.len() > 0 {
    heading(level: 2, lab(d, "tools_heading"))
    table(columns: (40mm, 24mm, 1fr), stroke: (x, y) => (bottom: 0.5pt + line-c),
      fill: (x, y) => if y == 0 { brand }, inset: 5pt,
      table.header(..(lab(d, "col_tool"), lab(d, "col_status"), lab(d, "col_detail")).map(h =>
        text(fill: white, weight: "semibold", size: 8pt, h))),
      ..ts.map(r => {
        let st = r.at("status", default: "error")
        let c = if st == "ok" { rgb("#15803d") } else if st == "partial" { rgb("#a16207") } else { danger }
        (str(r.at("tool", default: "")),
         text(fill: c, weight: "bold", size: 7.5pt, str(r.at("status_label", default: ""))),
         str(r.at("detail", default: "")))
      }).flatten())
  }
}
