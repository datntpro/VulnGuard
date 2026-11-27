// Minimal PR-1 template (PR-2 replaces the body with the real design).
// RULES: strings come ONLY from sys.inputs.data as values; no eval, no packages, no
// data-derived read()/image()/link()/label(). See tests/test_typst_template_lint.py.
#let d = json(bytes(sys.inputs.at("data")))
#set document(title: d.at("title", default: "VulnGuard"))
#set page(paper: "a4", margin: 18mm)
#set text(font: "DejaVu Sans", fallback: false, size: 9pt)
#show raw: set text(font: "DejaVu Sans Mono", ligatures: false, features: (calt: 0))
#heading(level: 1, d.at("title", default: ""))
#for f in d.at("findings", default: ()) [
  #heading(level: 2, f.at("title", default: ""))
  #text(f.at("description", default: ""))
  #if f.at("code", default: "") != "" [
    #raw(f.at("code"), block: true)
  ]
  #if f.at("evidence", default: "") != "" [
    #raw(f.at("evidence"), block: true)
  ]
]
