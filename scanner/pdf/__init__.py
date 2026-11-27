"""Typst PDF engine (hardened). Public API: ``scanner.pdf.engine.render``.

Design rules (see docs/wiki and tests/test_pdf_*.py):
  * scan strings reach Typst ONLY as JSON via ``sys.inputs`` -- never spliced into source, never eval'd;
  * compile always runs in a resource-limited worker subprocess, never in the API process;
  * root is a private temp dir built from copies (no symlinks), packages and network are blocked.
"""
