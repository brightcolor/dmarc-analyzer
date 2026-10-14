from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import create_model
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_client_ip, get_current_org, get_current_org_admin, get_current_user
from app.models import Organization, User
from app.services.audit import log_action
from app.services.org_settings import THRESHOLDS, ThresholdError, own_values, plain_number, save_thresholds
from app.templates_config import flash, templates

router = APIRouter(prefix="/settings", tags=["settings"])

ThresholdForm = create_model("ThresholdForm", **{t.name: (str, "") for t in THRESHOLDS})


def _page(request: Request, db: Session, user: User, org: Organization, form: dict[str, str] | None = None,
          error: str | None = None, status_code: int = 200):
    if form is None:
        form = {name: plain_number(value) for name, value in own_values(db, org.id).items()}
    groups: dict[str, list] = {}
    for threshold in THRESHOLDS:
        groups.setdefault(threshold.group, []).append(threshold)
    return templates.TemplateResponse(request, "settings/thresholds.html", {
        "user": user, "org": org, "error": error, "groups": groups, "form": form, "plain": plain_number,
        "page_title": "Schwellen",
    }, status_code=status_code)


@router.get("/thresholds", response_class=HTMLResponse)
def thresholds_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    return _page(request, db, user, org)


@router.post("/thresholds")
def save_thresholds_route(
    request: Request,
    data: Annotated[ThresholdForm, Form()],
    db: Session = Depends(get_db),
    user: User = Depends(get_current_org_admin),
    org: Organization = Depends(get_current_org),
):
    form = {name: value[:32] for name, value in data.model_dump().items()}
    try:
        changes = save_thresholds(db, org.id, form)
    except ThresholdError as exc:
        return _page(request, db, user, org, form, str(exc), 400)
    if changes:
        log_action(db, "thresholds.update", org_id=org.id, user_id=user.id, resource_type="organization",
                   resource_id=org.id, old_value={name: old for name, (old, _) in changes.items()},
                   new_value={name: new for name, (_, new) in changes.items()}, ip_address=get_client_ip(request))
    db.commit()
    flash(request, "ok", "Schwellen gespeichert" if changes else "Nichts geändert",
          "Empfehlungen, Alarme und Ampelfarben rechnen ab jetzt mit diesen Werten." if changes else
          "Die Werte waren schon so eingestellt.")
    return RedirectResponse(url="/settings/thresholds", status_code=303)
