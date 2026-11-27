#import "theme.typ": *

#let cover(d) = page(margin: 0pt, header: none, footer: none)[
  #let meta = d.at("meta")
  #let sm = d.at("summary")
  #block(fill: brand, width: 100%, height: 112mm, inset: (x: 18mm, top: 20mm))[
    #text(fill: white, weight: "bold", size: 11pt)[VulnGuard]
    #text(fill: rgb("#93c5fd"), size: 10pt)[ · #meta.at("org", default: "")]
    #v(28mm)
    #text(fill: rgb("#fcd34d"), size: 8.5pt, weight: "semibold", tracking: 2.4pt)[#lab(d, "kicker")]
    #v(2mm)
    #text(fill: white, size: 26pt, weight: "extrabold")[#meta.at("title", default: "")]
    #v(1mm)
    #text(fill: rgb("#cbd5e1"), size: 10.5pt)[#meta.at("subtitle", default: "")]
  ]
  #block(inset: (x: 18mm, y: 12mm), width: 100%)[
    #table(columns: (46mm, 1fr), stroke: (x, y) => (bottom: 0.5pt + line-c), inset: (x: 0pt, y: 6pt),
      ..meta.at("kv", default: ()).map(r => (text(fill: muted, weight: "medium", r.at(0)), r.at(1))).flatten())
    #v(8mm)
    #block(fill: rgb("#fef2f2"), stroke: (left: 3.5pt + danger), inset: 10pt, width: 100%, radius: (right: 4pt))[
      #text(size: 7pt, weight: "bold", fill: danger, tracking: 1.8pt)[#lab(d, "verdict_title")] \
      #text(size: 12.5pt, weight: "bold")[#sm.at("verdict", default: "")] \
      #text(size: 8.6pt, fill: rgb("#334155"))[#lab(d, "risk_score") *#sm.at("score_text", default: "")*]
    ]
  ]
  #place(bottom + left, dx: 18mm, dy: -12mm, block(width: 120mm,
    text(size: 7pt, fill: muted)[#lab(d, "disclaimer") #lab(d, "generated_at"): #meta.at("generated", default: "").]))
  #place(bottom + right, dx: -18mm, dy: -12mm,
    box(stroke: 1.2pt + danger, inset: (x: 8pt, y: 4pt), radius: 3pt,
      text(fill: danger, weight: "bold", size: 8pt, tracking: 1.5pt)[#lab(d, "confidential")]))
]
