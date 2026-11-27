"""Exceptions raised by the PDF engine. Messages never contain report content."""


class PdfEngineError(Exception):
    code = "pdf_render_failed"


class UnsafeRoot(PdfEngineError):
    code = "pdf_unsafe_root"


class PdfInputTooLarge(PdfEngineError):
    code = "pdf_input_too_large"


class PdfInvalidInput(PdfEngineError):
    code = "pdf_invalid_input"


class PdfCompileError(PdfEngineError):
    code = "pdf_compile_error"


class PdfTimeout(PdfEngineError):
    code = "pdf_timeout"


class PdfWorkerKilled(PdfEngineError):
    """Worker exceeded its memory budget or died on a resource limit."""

    code = "pdf_worker_killed"


class PdfOutputTooLarge(PdfEngineError):
    code = "pdf_output_too_large"


class PdfBusy(PdfEngineError):
    """All render slots taken; caller should answer 503/429 "busy" and retry later."""

    code = "pdf_busy"
