"""
File Processor
Extract text from various file types
"""

import os
import logging
from typing import Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# File size limits
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

SUPPORTED_TYPES = {
    # Code files
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "header",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",

    # Config files
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".conf": "config",
    ".cfg": "config",
    ".env": "env",

    # Markup
    ".md": "markdown",
    ".rst": "rst",
    ".xml": "xml",
    ".html": "html",

    # Data
    ".csv": "csv",
    ".tsv": "tsv",
    ".sql": "sql",

    # Shell
    ".sh": "shell",
    ".bash": "shell",
    ".dockerfile": "dockerfile",
    "dockerfile": "dockerfile",
    ".Dockerfile": "dockerfile",

    # Documents
    ".txt": "text",
    ".pdf": "pdf",
    ".docx": "docx",
}


def get_file_type(file_path: str) -> str:
    """Determine file type from extension"""
    path = Path(file_path)

    # Check full filename first (for Dockerfile)
    if path.name.lower() == "dockerfile":
        return "dockerfile"

    # Check extension
    ext = path.suffix.lower()
    return SUPPORTED_TYPES.get(ext, "unknown")


def is_supported_file(file_path: str) -> bool:
    """Check if file type is supported"""
    file_type = get_file_type(file_path)
    return file_type != "unknown"


async def extract_text_from_file(file_path: str) -> Tuple[str, int]:
    """
    Extract text content from file

    Args:
        file_path: Absolute path to file

    Returns:
        Tuple of (text_content, total_lines)

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file type not supported or file too large
        Exception: On extraction error
    """
    # Validate file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Not a file: {file_path}")

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")

    if file_size == 0:
        return "", 0

    file_type = get_file_type(file_path)

    if file_type == "unknown":
        raise ValueError(f"Unsupported file type: {file_path}")

    try:
        # Text-based files (most common)
        if file_type in ["python", "javascript", "typescript", "java", "cpp", "c", "go", "rs", "rb", "php",
                         "json", "yaml", "toml", "ini", "config", "env", "markdown", "rst", "xml", "html",
                         "csv", "tsv", "sql", "shell", "dockerfile", "text"]:
            return await _extract_text_file(file_path)

        # PDF
        elif file_type == "pdf":
            return await _extract_pdf(file_path)

        # DOCX
        elif file_type == "docx":
            return await _extract_docx(file_path)

        else:
            raise ValueError(f"Extraction not implemented for: {file_type}")

    except Exception as e:
        logger.error(f"Failed to extract {file_path}: {e}")
        raise


async def _extract_text_file(file_path: str) -> Tuple[str, int]:
    """Extract from plain text files"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        lines = content.split('\n')
        return content, len(lines)
    except Exception as e:
        logger.error(f"Failed to read text file {file_path}: {e}")
        raise


async def _extract_pdf(file_path: str) -> Tuple[str, int]:
    """Extract text from PDF"""
    try:
        try:
            from pypdf import PdfReader          # pypdf (có trong requirements)
        except ImportError:
            from PyPDF2 import PdfReader          # fallback tên cũ

        text_content = []
        with open(file_path, 'rb') as f:
            pdf_reader = PdfReader(f)
            for page in pdf_reader.pages:
                text_content.append(page.extract_text() or "")

        full_text = '\n'.join(text_content)
        lines = full_text.split('\n')
        return full_text, len(lines)

    except ImportError:
        raise Exception("Chưa cài thư viện đọc PDF. Cài: pip install pypdf")
    except Exception as e:
        logger.error(f"Failed to extract PDF {file_path}: {e}")
        raise


def extract_images_from_file(file_path: str, max_images: int = 10) -> list:
    """Trích các ảnh nhúng trong tài liệu .docx/.pdf → list bytes ảnh.

    .docx: ảnh nằm trong zip tại word/media/*.
    .pdf : dùng pypdf page.images (best-effort).
    Trả [] nếu không có ảnh hoặc không hỗ trợ.
    """
    ext = os.path.splitext(file_path)[1].lower()
    images: list = []
    try:
        if ext == ".docx":
            import zipfile
            img_exts = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".emf", ".wmf")
            with zipfile.ZipFile(file_path) as z:
                names = [n for n in z.namelist()
                         if n.startswith("word/media/") and n.lower().endswith(img_exts)]
                for n in sorted(names)[:max_images]:
                    # bỏ qua emf/wmf (vector cũ, vision model thường không đọc được)
                    if n.lower().endswith((".emf", ".wmf")):
                        continue
                    images.append(z.read(n))
        elif ext == ".pdf":
            try:
                from pypdf import PdfReader
            except ImportError:
                from PyPDF2 import PdfReader
            reader = PdfReader(file_path)
            for page in reader.pages:
                for img in getattr(page, "images", []):
                    images.append(img.data)
                    if len(images) >= max_images:
                        break
                if len(images) >= max_images:
                    break
    except Exception as e:
        logger.warning(f"Không trích được ảnh từ {file_path}: {e}")
    return images[:max_images]


async def _extract_docx(file_path: str) -> Tuple[str, int]:
    """Extract text from DOCX"""
    try:
        from docx import Document

        doc = Document(file_path)
        paragraphs = [p.text for p in doc.paragraphs]
        full_text = '\n'.join(paragraphs)

        lines = full_text.split('\n')
        return full_text, len(lines)

    except ImportError:
        raise Exception("python-docx not installed. Install with: pip install python-docx")
    except Exception as e:
        logger.error(f"Failed to extract DOCX {file_path}: {e}")
        raise


def get_supported_types_info() -> dict:
    """Get info about all supported file types"""
    return {
        "supported_extensions": list(SUPPORTED_TYPES.keys()),
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
        "categories": {
            "code": [".py", ".js", ".ts", ".java", ".go", ".rs"],
            "config": [".json", ".yaml", ".toml", ".env"],
            "markup": [".md", ".html", ".xml"],
            "data": [".csv", ".sql"],
            "documents": [".txt", ".pdf", ".docx"],
        }
    }
