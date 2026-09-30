"""Text from outside (mails, reports, DNS answers) made safe for the database and the interface."""
import re

# C0 control characters and DEL. PostgreSQL refuses NUL in text; the others only garble pages, logs and mails.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(value, size: int | None = None, *, lower: bool = False, single_line: bool = False) -> str:
    """Text every database takes: raw 8-bit bytes read as UTF-8, no control characters, at most size characters.

    Lowercasing comes before cutting, because some characters grow ("İ".lower() has two), and the cut has to
    hold for the database column.
    """
    text = "" if value is None else str(value)
    try:
        # Raw bytes the mail parser kept as surrogates turn back into their UTF-8 characters
        text = text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "replace").decode("utf-8")
    text = _CONTROL.sub("", text)
    if single_line:
        text = " ".join(text.split())
    if lower:
        text = text.lower()
    return text[:size] if size is not None else text
