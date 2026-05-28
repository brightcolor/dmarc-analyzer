# Import all models so SQLAlchemy's mapper registry is fully populated.
# This ordering avoids forward-reference issues.

from app.models.alert import AlertEvent, AlertRule  # noqa: F401
from app.models.api_token import ApiToken  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.base import Base  # noqa: F401
from app.models.dmarc_report import DmarcAuthResult, DmarcRecord, DmarcReport  # noqa: F401
from app.models.domain import Domain  # noqa: F401
from app.models.import_job import ImportError, ImportJob  # noqa: F401
from app.models.inbound_mail_address import InboundMailAddress  # noqa: F401
from app.models.notification import NotificationChannel, NotificationDelivery  # noqa: F401
from app.models.organization import (  # noqa: F401
    Organization,
    OrganizationMembership,
    PlanDefinition,
)
from app.models.settings import AppSettings  # noqa: F401
from app.models.smtp_inbound import (  # noqa: F401
    InboundMailAttachment,
    SmtpInboundMessage,
    SmtpInboundRejection,
)
from app.models.source_ip import SourceIp  # noqa: F401
from app.models.user import User  # noqa: F401

# Wire up back-references that require all models to be loaded
# (SQLAlchemy resolves string-based relationships lazily, so this just
# ensures all classes exist in the mapper registry before any query.)
