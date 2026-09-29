"""Senders with names: sources grouped by the service that sends for the organisation."""
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_analyst, get_current_org, get_current_user
from app.models import Organization, SourceIp, User
from app.services.alert_service import evaluate_rules_for_org
from app.services.audit import log_action
from app.services.senders import DECISIONS, decide, decisions, load_catalog, refresh_sources
from app.templates_config import flash, templates

router = APIRouter(prefix="/senders", tags=["senders"])

DECISION_DONE = {
    "trusted": "{name} ist freigegeben",
    "suspicious": "{name} gilt als verdächtig",
    "ignored": "{name} wird ignoriert",
    "reset": "Die Entscheidung über {name} ist aufgehoben",
}


@dataclass
class SenderRow:
    key: str | None
    name: str
    kind: str
    addresses: int
    unknown: int
    messages: int
    passed: int
    decision: str | None

    @property
    def rate(self) -> float | None:
        return self.passed / self.messages * 100 if self.messages else None


def _rows(db: Session, org: Organization) -> tuple[list[SenderRow], SenderRow | None]:
    catalog = load_catalog()
    decided = {key: approval.classification for key, approval in decisions(db, org.id).items()}
    grouped = (
        db.query(
            SourceIp.sender_key,
            func.count(SourceIp.id),
            func.sum(case((SourceIp.classification == "unknown", 1), else_=0)),
            func.coalesce(func.sum(SourceIp.total_messages), 0),
            func.coalesce(func.sum(SourceIp.pass_count), 0),
        )
        .filter(SourceIp.organization_id == org.id)
        .group_by(SourceIp.sender_key)
        .all()
    )
    rows, unassigned = [], None
    for key, addresses, unknown, messages, passed in grouped:
        sender = catalog.get(key)
        row = SenderRow(
            key=key, name=sender.name if sender else (key or "Nicht zugeordnet"),
            kind=sender.kind_label if sender else "", addresses=addresses, unknown=int(unknown or 0),
            messages=int(messages), passed=int(passed), decision=decided.get(key) if key else None,
        )
        if key is None:
            unassigned = row
        else:
            rows.append(row)
    rows.sort(key=lambda r: (-r.messages, r.name))
    return rows, unassigned


@router.get("", response_class=HTMLResponse)
def sender_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    rows, unassigned = _rows(db, org)
    total = sum(r.messages for r in rows) + (unassigned.messages if unassigned else 0)
    trusted = sum(r.messages for r in rows if r.decision == "trusted")
    waiting = db.query(func.count(SourceIp.id)).filter(
        SourceIp.organization_id == org.id, SourceIp.enriched_at.is_(None)
    ).scalar()
    return templates.TemplateResponse(request, "senders/index.html", {
        "user": user, "org": org,
        "rows": rows, "unassigned": unassigned, "waiting": waiting,
        "trusted_share": trusted / total * 100 if total else None,
        "catalog_problems": load_catalog().problems if user.is_superadmin else [],
        "lookup_enabled": settings.SENDER_LOOKUP_ENABLED,
        "interval": settings.SENDER_LOOKUP_INTERVAL_SECONDS,
        "page_title": "Absender",
    })


@router.post("/refresh")
def refresh_now(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst),
    org: Organization = Depends(get_current_org),
):
    result = refresh_sources(db, organization_id=org.id)
    if result.checked:
        evaluate_rules_for_org(db, org.id)
    db.commit()
    if result.checked:
        flash(request, "ok", "Absender erkannt", f"{result.checked} IP-Adressen geprüft, {result.identified} davon "
              "einem Absender zugeordnet.")
    else:
        flash(request, "ok", "Nichts zu tun", "Alle IP-Adressen sind schon zugeordnet.")
    return RedirectResponse(url="/senders", status_code=303)


@router.post("/{sender_key}/decide")
def decide_sender(
    request: Request,
    sender_key: str,
    decision: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst),
    org: Organization = Depends(get_current_org),
):
    catalog = load_catalog()
    if catalog.get(sender_key) is None:
        raise HTTPException(status_code=404)
    if decision not in (*DECISIONS, "reset"):
        raise HTTPException(status_code=400, detail="Diese Entscheidung gibt es nicht. Wähle freigeben, verdächtig, "
                            "ignorieren oder aufheben.")
    changed = decide(db, org.id, sender_key, decision, user.id)
    log_action(db, "sender.decide", org_id=org.id, user_id=user.id, resource_type="sender", resource_id=sender_key,
               new_value={"decision": decision, "addresses": changed}, ip_address=get_client_ip(request))
    db.commit()
    name = catalog.name(sender_key)
    if decision == "reset":
        text = f"{changed} IP-Adressen sind wieder offen. Einzeln eingestufte Adressen bleiben, wie sie sind."
    else:
        text = (f"Das gilt für {changed} IP-Adressen und für jede weitere, die dieser Dienst künftig nutzt. "
                "Einzeln eingestufte Adressen bleiben, wie sie sind.")
    flash(request, "ok", DECISION_DONE[decision].format(name=name), text)
    return RedirectResponse(url="/senders", status_code=303)
