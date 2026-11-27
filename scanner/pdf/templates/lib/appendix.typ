#import "theme.typ": *

#let appendix-section(d) = {
  heading(level: 1, lab(d, "appendix"))
  for s in d.at("appendix", default: ()) {
    heading(level: 2, s.at("title", default: ""))
    for p in s.at("paras", default: ()) { par(p) }
  }
}
