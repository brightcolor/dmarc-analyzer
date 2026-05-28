from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, get_current_org, get_client_ip
from app.models import ApiToken, Organization, User
from app.security import utcnow
from app.services.audit import log_action
from app.services.auth import create_api_token
from app.templates_config import templates

router = APIRouter(prefix="/api-tokens", tags=["api_tokens"])


@router.get("", response_class=HTMLResponse)
def token_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    tokens = (
        db.query(ApiToken)
        .filter_by(organization_id=org.id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )
    new_token = request.session.pop("new_api_token", None)
    return templates.TemplateResponse("api_tokens/index.html", {
        "request": request, "user": user, "org": org,
        "tokens": tokens, "new_token": new_token, "page_title": "API Tokens",
    })


@router.post("/new")
def create_token(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    count = db.query(ApiToken).filter_by(organization_id=org.id, is_active=True).count()
    if count >= org.max_api_tokens:
        raise HTTPException(status_code=400, detail="API token limit reached")

    raw, token = create_api_token(db, org.id, user.id, name.strip())

    log_action(
        db, "api_token.create", org_id=org.id, user_id=user.id,
        resource_type="api_token", resource_id=token.id,
        new_value={"name": name},
        ip_address=get_client_ip(request),
    )
    db.commit()

    # Show raw token exactly once via session flash
    request.session["new_api_token"] = raw
    return RedirectResponse(url="/api-tokens", status_code=303)


@router.post("/{token_id}/revoke")
def revoke_token(
    token_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    token = db.query(ApiToken).filter_by(id=token_id, organization_id=org.id).first()
    if not token:
        raise HTTPException(status_code=404)
    token.is_active = False
    token.revoked_at = utcnow()
    log_action(
        db, "api_token.revoke", org_id=org.id, user_id=user.id,
        resource_type="api_token", resource_id=token.id,
    )
    db.commit()
    return RedirectResponse(url="/api-tokens", status_code=303)
