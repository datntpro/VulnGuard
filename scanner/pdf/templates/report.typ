// VulnGuard report template (PR-2). One template for all report kinds.
// RULES: every string arrives ONLY via sys.inputs.data as values; never eval(), never
// read()/image()/json() with a data-derived argument, never package imports, no data-derived
// link/label/raw-lang. Enforced by tests/test_typst_template_lint.py.
#import "lib/theme.typ": *
#import "lib/cover.typ": cover
#import "lib/summary.typ": summary-section
#import "lib/finding.typ": detail-section
#import "lib/tables.typ": low-section
#import "lib/appendix.typ": appendix-section

#let d = json(bytes(sys.inputs.at("data")))
#let meta = d.at("meta", default: (:))

#set document(title: meta.at("title", default: "VulnGuard"), author: meta.at("org", default: "VulnGuard"))
#set text(font: ("Be Vietnam Pro", "DejaVu Sans"), fallback: false, size: 9.2pt, lang: d.at("lang", default: "vi"), fill: ink)
#set par(justify: false, leading: 0.62em, spacing: 0.9em)
#show raw: set text(font: ("JetBrains Mono", "DejaVu Sans"), size: 7.4pt, ligatures: false, features: (calt: 0))
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  block(below: 10pt, stroke: (bottom: 1.5pt + brand), inset: (bottom: 5pt), width: 100%,
    text(size: 15pt, weight: "extrabold", fill: brand, it))
}
#show heading.where(level: 2): it => block(above: 12pt, below: 6pt, sticky: true,
  text(size: 10.5pt, weight: "bold", fill: rgb("#334155"), it))

#cover(d)

#set page(paper: "a4", margin: (top: 22mm, bottom: 20mm, x: 16mm),
  header: context {
    let pg = here().page()
    let hs = query(heading.where(level: 1)).filter(h => h.location().page() <= pg and h.outlined)
    set text(size: 7.2pt, fill: muted)
    grid(columns: (1fr, auto), meta.at("title", default: ""), if hs.len() > 0 { hs.last().body })
    v(-4pt)
    line(length: 100%, stroke: 0.4pt + line-c)
  },
  footer: context {
    set text(size: 7.2pt)
    grid(columns: (1fr, auto),
      text(fill: danger, weight: "semibold", tracking: 0.8pt)[#lab(d, "confidential_footer") · #meta.at("org", default: "")],
      text(fill: muted)[#lab(d, "page") #counter(page).display() / #counter(page).final().first()])
  })

#heading(level: 1, outlined: false, lab(d, "toc"))
#outline(title: none, depth: 2, indent: 1.2em)

#heading(level: 1, lab(d, "summary"))
#summary-section(d)

#detail-section(d)
#low-section(d)
#appendix-section(d)
