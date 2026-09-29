from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_analyst, get_current_org, get_current_user
from app.models import DmarcRecord, DmarcReport, Organization, SourceIp, User
from app.services.senders import classify_manually, decisions, load_catalog
from app.templates_config import templates

router = APIRouter(prefix="/source-ips", tags=["source_ips"])


CLASSIFICATIONS = ("unknown", "trusted", "suspicious", "ignored")


def _paginate(q, page: int, per_page: int):
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, (total + per_page - 1) // per_page


@router.get("", response_class=HTMLResponse)
def source_ip_list(
    request: Request,
    page: int = Query(1, ge=1),
    classification: str | None = Query(None),
    search: str | None = Query(None),
    sender: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    catalog = load_catalog()
    q = db.query(SourceIp).filter_by(organization_id=org.id).order_by(
        SourceIp.total_messages.desc()
    )
    if classification in CLASSIFICATIONS:
        q = q.filter_by(classification=classification)
    if search:
        pattern = f"%{search.strip()}%"
        q = q.filter(or_(SourceIp.ip_address.ilike(pattern), SourceIp.reverse_dns.ilike(pattern)))
    present = sorted(
        (key for (key,) in db.query(SourceIp.sender_key).filter_by(organization_id=org.id).distinct() if key),
        key=lambda key: catalog.name(key).lower(),
    )
    if sender == "none":
        q = q.filter(SourceIp.sender_key.is_(None))
    elif sender in present:
        q = q.filter(SourceIp.sender_key == sender)
    else:
        sender = None

    ips, total, pages = _paginate(q, page, settings.UI_PAGE_SIZE)
    return templates.TemplateResponse(request, "source_ips/index.html", {
        "user": user, "org": org,
        "ips": ips, "total": total, "page": page, "pages": pages,
        "classification_filter": classification if classification in CLASSIFICATIONS else "",
        "classifications": CLASSIFICATIONS, "search": search or "",
        "sender_filter": sender or "", "senders": [(key, catalog.name(key)) for key in present],
        "catalog": catalog,
        "page_title": "IP-Adressen",
    })


@router.get("/{ip_id}", response_class=HTMLResponse)
def source_ip_detail(
    request: Request,
    ip_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    sip = db.query(SourceIp).filter_by(id=ip_id, organization_id=org.id).first()
    if not sip:
        raise HTTPException(status_code=404)

    # Recent records for this IP
    recent_records = (
        db.query(DmarcRecord)
        .join(DmarcReport)
        .filter(
            DmarcReport.organization_id == org.id,
            DmarcRecord.source_ip == sip.ip_address,
        )
        .order_by(DmarcReport.period_end.desc(), DmarcReport.created_at.desc())
        .limit(settings.UI_RECORDS_PAGE_SIZE)
        .all()
    )

    catalog = load_catalog()
    return templates.TemplateResponse(request, "source_ips/detail.html", {
        "user": user, "org": org,
        "sip": sip, "recent_records": recent_records, "classifications": CLASSIFICATIONS,
        "sender": catalog.get(sip.sender_key),
        "sender_decision": decisions(db, org.id).get(sip.sender_key) if sip.sender_key else None,
        "page_title": sip.ip_address,
    })


@router.post("/{ip_id}/classify")
def classify_ip(
    request: Request,
    ip_id: str,
    classification: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_analyst),
    org: Organization = Depends(get_current_org),
):
    sip = db.query(SourceIp).filter_by(id=ip_id, organization_id=org.id).first()
    if not sip:
        raise HTTPException(status_code=404)

    if classification not in CLASSIFICATIONS:
        raise HTTPException(status_code=400, detail="Diese Einstufung gibt es nicht. Wähle vertrauenswürdig, "
                            "unbekannt, verdächtig oder ignoriert.")

    if classification != sip.classification or sip.classification_source != "manual":
        classify_manually(sip, classification, user.id, db)
    sip.notes = notes.strip() or None
    db.commit()
    return RedirectResponse(url=f"/source-ips/{ip_id}", status_code=303)
