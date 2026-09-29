import logging
import secrets
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_SAMPLE_SECRET_KEYS = {"change_me_to_a_64_char_random_hex_string", "bitte-einen-eigenen-wert-setzen"}
_warnings: list[str] = []


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Compose passes variables of its own (ports, image tag) through the same .env
        extra="ignore",
    )

    # App
    APP_NAME: str = "DMARC Analyzer"
    APP_URL: str = "http://localhost:8000"
    DEBUG: bool = False
    SECRET_KEY: str = Field("", validate_default=True)
    TRUSTED_PROXIES: str = ""

    # Database
    DATABASE_URL: str = "sqlite:///./dmarc_analyzer.db"
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10

    # Session
    SESSION_COOKIE_NAME: str = "dmarc_session"
    SESSION_MAX_AGE: int = 86400 * 7  # 7 days
    SESSION_HTTPS_ONLY: bool = False
    SESSION_SAME_SITE: str = "lax"

    # Uploads
    UPLOAD_DIR: str = "./uploads"
    UPLOAD_MAX_SIZE: int = 10 * 1024 * 1024  # 10MB
    UPLOAD_ALLOWED_EXTENSIONS: str = ".xml,.xml.gz,.gz,.zip"
    UPLOAD_RATE_LIMIT: str = "20/minute"

    # SMTP Inbound
    SMTP_INBOUND_ENABLED: bool = True
    SMTP_INBOUND_BIND: str = "0.0.0.0"  # noqa: S104
    SMTP_INBOUND_PORT: int = 2525
    SMTP_INBOUND_DOMAIN: str = "reports.example.org"
    SMTP_INBOUND_MAX_MESSAGE_SIZE: int = 10 * 1024 * 1024  # 10MB
    SMTP_INBOUND_MAX_RECIPIENTS: int = 1
    SMTP_INBOUND_REJECT_UNKNOWN: bool = True
    SMTP_INBOUND_STORE_RAW: bool = False
    SMTP_INBOUND_RAW_RETENTION_DAYS: int = 7
    SMTP_INBOUND_RATE_LIMIT_PER_IP: int = 60       # per hour
    SMTP_INBOUND_RATE_LIMIT_PER_RECIPIENT: int = 120  # per hour
    SMTP_INBOUND_TLS_ENABLED: bool = False
    SMTP_INBOUND_TLS_CERT_PATH: str | None = None
    SMTP_INBOUND_TLS_KEY_PATH: str | None = None

    # Raw mail storage (when STORE_RAW=true)
    RAW_MAIL_DIR: str = "./raw_mail"

    # Alert scheduler
    ALERT_EVAL_INTERVAL_SECONDS: int = 300  # 5 minutes
    NOTIFICATION_RETRY_MAX: int = 3

    # First-run setup and accounts
    SETUP_CODE_LENGTH: int = Field(
        12, ge=8, le=32, description="Anzahl Zeichen des Einrichtungscodes für das erste Administratorkonto.",
    )
    SETUP_OPEN_PATHS: str = Field(
        "/static,/api,/health,/ready,/metrics,/webhook,/favicon.ico",
        description="Pfade, die während der Ersteinrichtung erreichbar bleiben, durch Komma getrennt.",
    )
    PASSWORD_MIN_LENGTH: int = Field(10, ge=8, le=64, description="Mindestlänge für Passwörter.")

    # API
    API_RATE_LIMIT: str = "100/minute"
    API_TOKEN_EXPIRE_DAYS: int = 365

    # DNS enrichment (optional)
    DNS_ENRICHMENT_ENABLED: bool = False
    DNS_ENRICHMENT_TIMEOUT: float = 2.0
    DNS_ENRICHMENT_RATE_LIMIT: int = 10  # per minute

    # Feature flags
    FEATURE_DOMAIN_VERIFICATION: bool = True
    FEATURE_SOURCE_ENRICHMENT: bool = False
    FEATURE_SAAS_MODE: bool = False

    # Display
    DISPLAY_TIMEZONE: str = Field(
        "Europe/Berlin", description="Zeitzone für alle Zeitangaben in der Oberfläche, z. B. Europe/Berlin oder UTC.",
    )
    UI_PASS_RATE_GOOD: float = Field(
        95.0, ge=0.0, le=100.0, description="Bestehensquote in Prozent, ab der die Oberfläche sie grün zeigt.",
    )
    UI_PASS_RATE_WARN: float = Field(
        75.0, ge=0.0, le=100.0,
        description="Bestehensquote in Prozent, ab der die Oberfläche sie gelb zeigt; darunter rot.",
    )
    UI_CHART_DAYS: int = Field(
        30, ge=7, le=365, description="Anzahl Tage im Verlaufsdiagramm auf Übersicht und Domainseite.",
    )
    UI_PAGE_SIZE: int = Field(25, ge=5, le=500, description="Einträge je Seite in Listen.")
    UI_RECENT_LIMIT: int = Field(
        10, ge=3, le=100, description="Einträge in Kurzlisten wie „Letzte Berichte“ und „Letzte Importe“.",
    )
    UI_RECORDS_PAGE_SIZE: int = Field(
        50, ge=5, le=1000, description="Datensätze je Seite in der Detailansicht eines Berichts.",
    )

    # Archive limits for report attachments and uploads
    ARCHIVE_MAX_ATTACHMENT_BYTES: int = Field(
        20 * 1024 * 1024, ge=1024 * 1024, le=200 * 1024 * 1024,
        description="Größter Mailanhang in Bytes, der noch ausgewertet wird. Größere Anhänge werden übersprungen.",
    )
    ARCHIVE_MAX_UNPACKED_BYTES: int = Field(
        50 * 1024 * 1024, ge=1024 * 1024, le=1024 * 1024 * 1024,
        description="Höchstgröße in Bytes nach dem Entpacken von ZIP oder GZ. Schützt vor Archivbomben.",
    )
    ARCHIVE_MAX_FILES: int = Field(
        50, ge=1, le=10_000, description="Höchstzahl Dateien in einem ZIP-Archiv.",
    )

    # Report parsing
    DMARC_MAX_RECORDS_PER_REPORT: int = Field(
        50_000, ge=100, le=1_000_000,
        description="Höchstzahl der Datensätze je Bericht. Weitere Datensätze werden verworfen und protokolliert.",
    )

    # Recommendations
    RECOMMENDATION_WINDOW_DAYS: int = Field(
        30, ge=1, le=365, description="Zeitraum in Tagen, den die Empfehlungen je Domain auswerten.",
    )
    RECOMMENDATION_STALE_REPORT_DAYS: int = Field(
        7, ge=1, le=90, description="Nach so vielen Tagen ohne Bericht meldet die Domain „keine neuen Berichte“.",
    )
    RECOMMENDATION_MIN_MESSAGES: int = Field(
        100, ge=1, le=10_000_000,
        description="Mindestzahl Nachrichten im Zeitraum, bevor eine strengere Policy empfohlen wird.",
    )
    RECOMMENDATION_QUARANTINE_PASS_RATE: float = Field(
        95.0, ge=50.0, le=100.0, description="Bestehensquote in Prozent, ab der p=quarantine empfohlen wird.",
    )
    RECOMMENDATION_REJECT_PASS_RATE: float = Field(
        99.0, ge=50.0, le=100.0, description="Bestehensquote in Prozent, ab der p=reject empfohlen wird.",
    )
    RECOMMENDATION_HIGH_FAIL_RATE: float = Field(
        20.0, ge=0.0, le=100.0, description="Fehlerquote in Prozent, ab der eine Domain als auffällig gilt.",
    )
    RECOMMENDATION_ENFORCED_FAIL_RATE: float = Field(
        10.0, ge=0.0, le=100.0,
        description="Fehlerquote in Prozent, ab der eine aktive quarantine- oder reject-Policy als riskant gilt.",
    )
    RECOMMENDATION_FAIL_MIN_MESSAGES: int = Field(
        20, ge=1, le=10_000_000, description="Mindestzahl Nachrichten, bevor Fehlerquoten bewertet werden.",
    )
    RECOMMENDATION_SPF_ONLY_SHARE: float = Field(
        5.0, ge=0.0, le=100.0,
        description="Anteil in Prozent der Nachrichten, die nur per SPF bestehen, ab dem DKIM empfohlen wird.",
    )

    @field_validator("SECRET_KEY")
    @classmethod
    def _usable_secret(cls, value: str) -> str:
        # An empty or published sample key would let anyone sign session cookies
        if len(value) < 32 or value in _SAMPLE_SECRET_KEYS:
            _warnings.append(
                "SECRET_KEY fehlt, ist zu kurz oder stammt aus der Vorlage. Die Anwendung nutzt einen zufälligen "
                "Schlüssel; Anmeldungen gelten deshalb nur bis zum nächsten Neustart. Setze in der .env einen "
                "eigenen Wert, etwa mit: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
            return secrets.token_hex(32)
        return value

    @field_validator("DISPLAY_TIMEZONE")
    @classmethod
    def _known_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except Exception as exc:
            raise ValueError(f"unbekannte Zeitzone {value!r}, erwartet wird etwa Europe/Berlin oder UTC") from exc
        return value

    @model_validator(mode="after")
    def _rate_order(self):
        if self.UI_PASS_RATE_WARN > self.UI_PASS_RATE_GOOD:
            raise ValueError("UI_PASS_RATE_WARN darf nicht über UI_PASS_RATE_GOOD liegen")
        return self

    @property
    def upload_dir_path(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def raw_mail_dir_path(self) -> Path:
        p = Path(self.RAW_MAIL_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def setup_open_paths(self) -> list[str]:
        return [p.strip() for p in self.SETUP_OPEN_PATHS.split(",") if p.strip().startswith("/")]

    @property
    def allowed_upload_extensions(self) -> set[str]:
        return {ext.strip() for ext in self.UPLOAD_ALLOWED_EXTENSIONS.split(",") if ext.strip()}


_VALIDATION_MESSAGES = {
    "greater_than_equal": "muss mindestens {ge} sein",
    "less_than_equal": "darf höchstens {le} sein",
    "int_parsing": "muss eine ganze Zahl sein",
    "float_parsing": "muss eine Zahl sein",
    "bool_parsing": "muss true oder false sein",
}
_VALIDATION_PREFIX = "Value error, "


def _describe_error(error: dict) -> str:
    name = ".".join(str(part) for part in error.get("loc", ())) or "?"
    template = _VALIDATION_MESSAGES.get(error.get("type", ""))
    if template:
        reason = template.format(**error.get("ctx", {}))
    else:
        reason = error.get("msg", "ist ungültig").removeprefix(_VALIDATION_PREFIX)
    if error.get("type") == "value_error" and not error.get("loc"):
        return f"- {reason}"
    return f"- {name}: {reason} (gesetzt: {error.get('input')!r})"


def load_settings() -> Settings:
    try:
        loaded = Settings()
    except ValidationError as exc:
        details = "\n".join(_describe_error(err) for err in exc.errors())
        sys.exit(
            "Die Anwendung startet nicht, weil Einstellungen ungültig sind:\n"
            f"{details}\n"
            "Bitte die Werte in der .env-Datei oder den Umgebungsvariablen korrigieren und neu starten."
        )
    for message in _warnings:
        logging.getLogger("app.config").warning(message)
    _warnings.clear()
    return loaded


settings = load_settings()
