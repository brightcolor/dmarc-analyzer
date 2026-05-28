import secrets
from pathlib import Path

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


settings = Settings()
