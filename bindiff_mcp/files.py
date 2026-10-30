"""File helpers shared by exports, diffs and job records."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path


def staging_path(path: Path) -> Path:
    """A unique hidden sibling of ``path``, written before it is renamed into place.

    The real suffix stays last: the BinExport plugin is handed this name too.
    """
    return path.with_name(f".{path.stem}.{uuid.uuid4().hex[:8]}.partial{path.suffix}")


def write_text_atomic(path: Path, text: str) -> None:
    """Replace ``path`` with ``text``; readers never see a partial file."""
    staging = staging_path(path)
    try:
        staging.write_text(text, encoding="utf-8")
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
