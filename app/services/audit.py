"""Audit logging service."""
import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    action: str,
    *,
    org_id: str | None = None,
    user_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    old_value: Any | None = None,
    new_value: Any | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    try:
        entry = AuditLog(
            organization_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            old_value=json.dumps(old_value) if old_value is not None else None,
            new_value=json.dumps(new_value) if new_value is not None else None,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,
        )
        db.add(entry)
        db.flush()
    except Exception as exc:
        logger.warning("Failed to write audit log: %s", exc)
