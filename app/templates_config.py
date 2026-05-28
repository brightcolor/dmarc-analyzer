"""Shared Jinja2 template configuration."""
import json
from datetime import datetime

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")


def _format_datetime(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if value is None:
        return "—"
    return value.strftime(fmt)


def _format_date(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d")


def _filesizeformat(value: int | None) -> str:
    if value is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _pct_color(rate: float | None) -> str:
    if rate is None:
        return "secondary"
    if rate >= 95:
        return "success"
    if rate >= 75:
        return "warning"
    return "danger"


def _severity_badge(severity: str) -> str:
    colors = {"info": "info", "warning": "warning", "critical": "danger"}
    return colors.get(severity, "secondary")


def _tojson(value) -> str:
    return json.dumps(value)


# Register filters
templates.env.filters["datetime"] = _format_datetime
templates.env.filters["date"] = _format_date
templates.env.filters["filesizeformat"] = _filesizeformat
templates.env.filters["pct_color"] = _pct_color
templates.env.filters["severity_badge"] = _severity_badge
templates.env.filters["tojson"] = _tojson
templates.env.globals["now"] = datetime.utcnow
