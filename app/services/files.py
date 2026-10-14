"""Helpers for writing received files to disk."""
import re
from pathlib import PurePath

MAX_NAME_LENGTH = 120


def safe_filename(name: str | None, fallback: str = "bericht") -> str:
    """File name without directories and with a plain character set, for storing on disk."""
    base = PurePath((name or "").replace("\\", "/")).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")[:MAX_NAME_LENGTH]
    return cleaned or fallback
