import logging
import secrets
import sys
from pathlib import Path
from typing import Literal
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
    SMTP_INBOUND_RAW_RETENTION_DAYS: int = Field(
        7, ge=1, le=3650, description="Tage, die gespeicherte Rohmails aufbewahrt werden.",
    )
    SMTP_REJECTION_RETENTION_DAYS: int = Field(
        30, ge=1, le=3650, description="Tage, die abgelehnte Zustellversuche in der Liste bleiben.",
    )
    SMTP_INBOUND_RATE_LIMIT_PER_IP: int = 60       # per hour
    SMTP_INBOUND_RATE_LIMIT_PER_RECIPIENT: int = 120  # per hour
    SMTP_INBOUND_TLS_ENABLED: bool = False
    SMTP_INBOUND_TLS_CERT_PATH: str | None = None
    SMTP_INBOUND_TLS_KEY_PATH: str | None = None

    # Raw mail storage (when STORE_RAW=true)
    RAW_MAIL_DIR: str = "./raw_mail"

    # Scheduler in the web process
    SCHEDULER_ENABLED: bool = Field(
        True, description="Zeitplaner für Alarme, Benachrichtigungen, Aufräumen und Wochenbericht einschalten.",
    )
    SCHEDULER_TICK_SECONDS: int = Field(
        30, ge=5, le=3600, description="Abstand in Sekunden, in dem der Zeitplaner nach fälligen Aufgaben sieht.",
    )
    ALERT_EVAL_INTERVAL_SECONDS: int = Field(
        300, ge=60, le=86_400, description="Abstand in Sekunden zwischen zwei Prüfungen aller Alarmregeln.",
    )
    NOTIFICATION_DISPATCH_INTERVAL_SECONDS: int = Field(
        60, ge=10, le=3600, description="Abstand in Sekunden, in dem wartende Benachrichtigungen verschickt werden.",
    )
    NOTIFICATION_RETRY_MAX: int = Field(
        3, ge=0, le=20, description="Wie oft eine fehlgeschlagene Benachrichtigung erneut versucht wird.",
    )
    NOTIFICATION_RETRY_DELAY_SECONDS: int = Field(
        300, ge=10, le=86_400,
        description="Wartezeit in Sekunden vor dem ersten neuen Versuch; jeder weitere wartet doppelt so lange.",
    )
    NOTIFICATION_BATCH_SIZE: int = Field(
        100, ge=1, le=10_000, description="Höchstzahl Benachrichtigungen, die ein Lauf verschickt.",
    )
    NOTIFICATION_HTTP_TIMEOUT_SECONDS: int = Field(
        10, ge=1, le=120, description="Zeitlimit in Sekunden für Webhook, ntfy und Slack.",
    )
    NTFY_DEFAULT_URL: str = Field(
        "https://ntfy.sh", description="ntfy-Server für Kanäle, die keinen eigenen Server angeben.",
    )
    RETENTION_INTERVAL_SECONDS: int = Field(
        86_400, ge=3600, le=604_800, description="Abstand in Sekunden zwischen zwei Aufräumläufen.",
    )
    RETENTION_BATCH_SIZE: int = Field(
        1000, ge=10, le=100_000, description="Höchstzahl Berichte, die ein Aufräumlauf löscht.",
    )

    # Alert defaults for rules without their own threshold
    ALERT_DEFAULT_FAIL_RATE: float = Field(
        10.0, ge=0.0, le=100.0, description="DMARC-Fehlerquote in Prozent, ab der eine Regel ohne Schwelle auslöst.",
    )
    ALERT_DEFAULT_AUTH_FAIL_RATE: float = Field(
        20.0, ge=0.0, le=100.0,
        description="Anteil in Prozent ohne passendes SPF bzw. DKIM, ab dem eine Regel ohne Schwelle auslöst.",
    )
    ALERT_DEFAULT_HIGH_VOLUME: int = Field(
        500, ge=1, le=100_000_000, description="Nachrichten, ab denen eine neue Quelle als groß gilt.",
    )
    ALERT_DEFAULT_VOLUME_SPIKE: float = Field(
        200.0, ge=1.0, le=10_000.0,
        description="Anstieg in Prozent über dem Durchschnitt, ab dem Alarm ausgelöst wird.",
    )
    ALERT_DEFAULT_VOLUME_DROP: float = Field(
        80.0, ge=1.0, le=100.0, description="Rückgang in Prozent unter den Durchschnitt, ab dem Alarm ausgelöst wird.",
    )
    ALERT_VOLUME_BASELINE_WINDOWS: int = Field(
        7, ge=1, le=90, description="Anzahl früherer Zeiträume, aus denen der Durchschnitt für Mengenalarme entsteht.",
    )
    ALERT_DEFAULT_INVALID_RECIPIENTS: int = Field(
        20, ge=1, le=1_000_000, description="Abgelehnte Mails an unbekannte Adressen, ab denen Alarm ausgelöst wird.",
    )
    ALERT_DEFAULT_RATE_LIMIT_HITS: int = Field(
        10, ge=1, le=1_000_000, description="Treffer der Mailgrenze, ab denen Alarm ausgelöst wird.",
    )
    ALERT_DEFAULT_NEW_SOURCE_FAILURES: int = Field(
        1, ge=1, le=1_000_000,
        description="Nicht bestandene Nachrichten einer neuen Quelle, ab denen Alarm ausgelöst wird.",
    )
    ALERT_DEFAULT_IMPORT_FAILURES: int = Field(
        1, ge=1, le=10_000, description="Fehlgeschlagene Importe, ab denen Alarm ausgelöst wird.",
    )

    # Outgoing mail for alerts and the weekly digest
    MAIL_SMTP_HOST: str = Field(
        "", description="SMTP-Server für ausgehende Mails. Leer lassen schaltet den Mailversand aus.",
    )
    MAIL_SMTP_PORT: int = Field(587, ge=1, le=65_535, description="Port des SMTP-Servers.")
    MAIL_SMTP_SECURITY: Literal["starttls", "ssl", "none"] = Field(
        "starttls", description="Verschlüsselung zum SMTP-Server: starttls, ssl oder none.",
    )
    MAIL_SMTP_USER: str = Field("", description="Benutzername am SMTP-Server; leer ohne Anmeldung.")
    MAIL_SMTP_PASSWORD: str = Field("", description="Passwort am SMTP-Server.")
    MAIL_FROM: str = Field("DMARC Analyzer <dmarc@example.org>", description="Absender der Mails.")
    MAIL_TIMEOUT_SECONDS: int = Field(20, ge=1, le=300, description="Zeitlimit in Sekunden für den SMTP-Server.")

    # Weekly digest
    DIGEST_WEEKDAY: int = Field(0, ge=0, le=6, description="Wochentag des Wochenberichts, 0 = Montag bis 6 = Sonntag.")
    DIGEST_HOUR: int = Field(
        8, ge=0, le=23, description="Stunde, ab der der Wochenbericht verschickt wird (DISPLAY_TIMEZONE).",
    )
    DIGEST_PERIOD_DAYS: int = Field(7, ge=1, le=31, description="Tage, die der Wochenbericht zusammenfasst.")
    DIGEST_CHECK_INTERVAL_SECONDS: int = Field(
        900, ge=60, le=86_400, description="Abstand in Sekunden, in dem der Zeitplaner fällige Wochenberichte sucht.",
    )
    DIGEST_LIST_LIMIT: int = Field(
        5, ge=1, le=50, description="Einträge je Liste im Wochenbericht: Quellen, Alarme und Empfehlungen.",
    )

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

    @field_validator("NTFY_DEFAULT_URL")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("muss mit http:// oder https:// beginnen, etwa https://ntfy.sh")
        return value.rstrip("/")

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
    "literal_error": "muss einer dieser Werte sein: {expected}",
}
_VALIDATION_PREFIX = "Value error, "


def _describe_error(error: dict) -> str:
    name = ".".join(str(part) for part in error.get("loc", ())) or "?"
    template = _VALIDATION_MESSAGES.get(error.get("type", ""))
    if template:
        ctx = {key: str(value).replace(" or ", " oder ") for key, value in error.get("ctx", {}).items()}
        reason = template.format(**ctx)
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
