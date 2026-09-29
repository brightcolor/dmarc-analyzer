import secrets
import sys
from pathlib import Path

from pydantic import Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # App
    APP_NAME: str = "DMARC Analyzer"
    APP_URL: str = "http://localhost:8000"
    DEBUG: bool = False
    SECRET_KEY: str = secrets.token_hex(32)
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

    # Initial super admin (created on first run if not exists)
    INITIAL_ADMIN_EMAIL: str | None = None
    INITIAL_ADMIN_PASSWORD: str | None = None

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
    def allowed_upload_extensions(self) -> set[str]:
        return {ext.strip() for ext in self.UPLOAD_ALLOWED_EXTENSIONS.split(",") if ext.strip()}


_VALIDATION_MESSAGES = {
    "greater_than_equal": "muss mindestens {ge} sein",
    "less_than_equal": "darf höchstens {le} sein",
    "int_parsing": "muss eine ganze Zahl sein",
    "float_parsing": "muss eine Zahl sein",
    "bool_parsing": "muss true oder false sein",
}


def _describe_error(error: dict) -> str:
    name = ".".join(str(part) for part in error.get("loc", ())) or "?"
    template = _VALIDATION_MESSAGES.get(error.get("type", ""))
    reason = template.format(**error.get("ctx", {})) if template else error.get("msg", "ist ungültig")
    return f"- {name}: {reason} (gesetzt: {error.get('input')!r})"


def load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        details = "\n".join(_describe_error(err) for err in exc.errors())
        sys.exit(
            "Die Anwendung startet nicht, weil Einstellungen ungültig sind:\n"
            f"{details}\n"
            "Bitte die Werte in der .env-Datei oder den Umgebungsvariablen korrigieren und neu starten."
        )


settings = load_settings()
