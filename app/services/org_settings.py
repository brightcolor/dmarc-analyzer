"""Thresholds an organisation sets for itself; without its own value the one from the .env applies."""
import logging
from dataclasses import dataclass
from types import SimpleNamespace

from annotated_types import Ge, Le
from sqlalchemy.orm import Session

from app.config import Settings, settings
from app.models import AppSettings

logger = logging.getLogger(__name__)

KEY_PREFIX = "threshold."


@dataclass(frozen=True)
class Threshold:
    name: str
    label: str
    unit: str
    group: str

    @property
    def field(self):
        return Settings.model_fields[self.name]

    @property
    def kind(self) -> type:
        return self.field.annotation

    @property
    def bounds(self) -> tuple[float, float]:
        lower = next(m.ge for m in self.field.metadata if isinstance(m, Ge))
        upper = next(m.le for m in self.field.metadata if isinstance(m, Le))
        return lower, upper

    @property
    def description(self) -> str:
        return self.field.description or ""

    @property
    def default(self) -> int | float:
        return getattr(settings, self.name)


THRESHOLDS = (
    Threshold("UI_PASS_RATE_GOOD", "Grün ab", "%", "Ampel"),
    Threshold("UI_PASS_RATE_WARN", "Gelb ab", "%", "Ampel"),
    Threshold("RECOMMENDATION_QUARANTINE_PASS_RATE", "p=quarantine empfehlen ab", "%", "Empfehlungen"),
    Threshold("RECOMMENDATION_REJECT_PASS_RATE", "p=reject empfehlen ab", "%", "Empfehlungen"),
    Threshold("RECOMMENDATION_MIN_MESSAGES", "Nachrichten für eine Policy-Empfehlung", "Nachrichten",
              "Empfehlungen"),
    Threshold("RECOMMENDATION_HIGH_FAIL_RATE", "Auffällige Fehlerquote ab", "%", "Empfehlungen"),
    Threshold("RECOMMENDATION_ENFORCED_FAIL_RATE", "Riskante Fehlerquote bei quarantine oder reject ab", "%",
              "Empfehlungen"),
    Threshold("RECOMMENDATION_FAIL_MIN_MESSAGES", "Nachrichten für eine Fehlerquote", "Nachrichten",
              "Empfehlungen"),
    Threshold("RECOMMENDATION_SPF_ONLY_SHARE", "DKIM empfehlen ab Anteil nur per SPF", "%", "Empfehlungen"),
    Threshold("RECOMMENDATION_WINDOW_DAYS", "Ausgewerteter Zeitraum", "Tage", "Empfehlungen"),
    Threshold("RECOMMENDATION_STALE_REPORT_DAYS", "„Keine neuen Berichte“ nach", "Tage", "Empfehlungen"),
)
BY_NAME = {t.name: t for t in THRESHOLDS}

# Pairs (lower, upper) whose order the evaluation relies on
ORDERED = (
    ("UI_PASS_RATE_WARN", "UI_PASS_RATE_GOOD"),
    ("RECOMMENDATION_QUARANTINE_PASS_RATE", "RECOMMENDATION_REJECT_PASS_RATE"),
)


class ThresholdError(ValueError):
    pass


def _parse(threshold: Threshold, raw: str) -> int | float:
    text = raw.strip().replace(",", ".")
    try:
        value = float(text) if threshold.kind is float else int(text)
    except ValueError:
        kind = "eine ganze Zahl" if threshold.kind is int else "eine Zahl"
        raise ThresholdError(f"{threshold.label}: „{raw.strip()}“ ist keine gültige Angabe, erwartet wird {kind}.") \
            from None
    lower, upper = threshold.bounds
    if not lower <= value <= upper:
        raise ThresholdError(f"{threshold.label}: erlaubt sind {_plain(lower)} bis {_plain(upper)} {threshold.unit}.")
    return value


def plain_number(value: int | float | None) -> str:
    """A number as typed into a form: 95 instead of 95.0, never in exponent notation."""
    if value is None:
        return ""
    return str(int(value)) if float(value).is_integer() else str(value)


def _plain(value: int | float) -> str:
    return plain_number(value).replace(".", ",")


def own_values(db: Session, org_id: str) -> dict[str, int | float]:
    """The organisation's own values; unreadable entries are skipped and the .env applies."""
    rows = db.query(AppSettings).filter(AppSettings.organization_id == org_id,
                                        AppSettings.key.startswith(KEY_PREFIX)).all()
    values = {}
    for row in rows:
        threshold = BY_NAME.get(row.key.removeprefix(KEY_PREFIX))
        if threshold is None or row.value is None:
            continue
        try:
            values[threshold.name] = _parse(threshold, row.value)
        except ThresholdError:
            logger.warning("Ignoring stored threshold %s=%r for organisation %s", row.key, row.value, org_id)
    return values


def thresholds_for(db: Session, org_id: str | None) -> SimpleNamespace:
    """Every threshold with the value that applies to the organisation, read like `settings`."""
    values = {t.name: t.default for t in THRESHOLDS}
    if org_id:
        values.update(own_values(db, org_id))
    return SimpleNamespace(**values)


def save_thresholds(db: Session, org_id: str, form: dict[str, str]) -> dict[str, tuple]:
    """Store the filled fields, remove the empty ones; returns the changes as name -> (before, after)."""
    wanted: dict[str, int | float | None] = {}
    problems = []
    for threshold in THRESHOLDS:
        raw = form.get(threshold.name, "")
        if not raw.strip():
            wanted[threshold.name] = None
            continue
        try:
            wanted[threshold.name] = _parse(threshold, raw)
        except ThresholdError as exc:
            problems.append(str(exc))
    if problems:
        raise ThresholdError(" ".join(problems))

    effective = {name: BY_NAME[name].default if value is None else value for name, value in wanted.items()}
    for lower, upper in ORDERED:
        own = wanted[lower] is not None or wanted[upper] is not None
        if own and effective[lower] > effective[upper]:
            raise ThresholdError(f"{BY_NAME[lower].label} darf nicht über {BY_NAME[upper].label} liegen "
                                 f"({_plain(effective[lower])} gegen {_plain(effective[upper])} %).")

    before = own_values(db, org_id)
    rows = {row.key: row for row in db.query(AppSettings).filter(AppSettings.organization_id == org_id,
                                                                  AppSettings.key.startswith(KEY_PREFIX))}
    for name, value in wanted.items():
        key = KEY_PREFIX + name
        row = rows.get(key)
        if value is None:
            if row is not None:
                db.delete(row)
        elif row is None:
            db.add(AppSettings(key=key, value=str(value), organization_id=org_id,
                               description=BY_NAME[name].label))
        else:
            row.value = str(value)
    return {name: (before.get(name), value) for name, value in wanted.items() if before.get(name) != value}
