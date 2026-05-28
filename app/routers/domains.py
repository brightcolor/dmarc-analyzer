import re
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, get_current_org, get_client_ip
from app.models import Domain, InboundMailAddress, Organization, User
from app.services.audit import log_action
from app.services.inbound_address import create_domain_address, create_org_address
from app.services.recommendation import get_recommendations_for_domain
from app.services.dashboard import get_pass_fail_over_time
from app.templates_config import templates
from app.config import settings

router = APIRouter(prefix="/domains", tags=["domains"])

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _paginate(q, page: int, per_page: int = 25):
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, (total + per_page - 1) // per_page


@router.get("", response_class=HTMLResponse)
def domain_list(
    request: Request,
    page: int = Query(1, ge=1),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    q = db.query(Domain).filter_by(organization_id=org.id)
    if search:
        q = q.filter(Domain.name.ilike(f"%{search}%"))
    q = q.order_by(Domain.name)
    domains, total, pages = _paginate(q, page)

    return templates.TemplateResponse("domains/index.html", {
        "request": request, "user": user, "org": org,
        "domains": domains, "total": total, "page": page, "pages": pages,
        "search": search or "", "page_title": "Domains",
    })


@router.get("/new", response_class=HTMLResponse)
def domain_new_form(
    request: Request,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    return templates.TemplateResponse("domains/form.html", {
        "request": request, "user": user, "org": org,
        "domain": None, "page_title": "Add Domain",
    })


@router.post("/new")
def domain_create(
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    name = name.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(name):
        return templates.TemplateResponse("domains/form.html", {
            "request": request, "user": user, "org": org,
            "error": "Invalid domain name.", "domain": None, "page_title": "Add Domain",
        })

    existing = db.query(Domain).filter_by(organization_id=org.id, name=name).first()
    if existing:
        return templates.TemplateResponse("domains/form.html", {
            "request": request, "user": user, "org": org,
            "error": "Domain already exists.", "domain": None, "page_title": "Add Domain",
        })

    # Check limit
    count = db.query(Domain).filter_by(organization_id=org.id).count()
    if count >= org.max_domains:
        return templates.TemplateResponse("domains/form.html", {
            "request": request, "user": user, "org": org,
            "error": f"Domain limit reached ({org.max_domains}).", "domain": None,
            "page_title": "Add Domain",
        })

    domain = Domain(organization_id=org.id, name=name, is_active=True)
    db.add(domain)
    db.flush()

    # Auto-create domain-specific inbound address
    addr = create_domain_address(db, org, domain)

    log_action(
        db, "domain.create", org_id=org.id, user_id=user.id,
        resource_type="domain", resource_id=domain.id,
        new_value={"name": name},
        ip_address=get_client_ip(request),
    )
    db.commit()
    return RedirectResponse(url=f"/domains/{domain.id}", status_code=303)


@router.get("/{domain_id}", response_class=HTMLResponse)
def domain_detail(
    request: Request,
    domain_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)

    # Inbound addresses for this domain
    addresses = db.query(InboundMailAddress).filter_by(
        organization_id=org.id, domain_id=domain_id
    ).all()

    # Recommendations
    recs = get_recommendations_for_domain(db, org.id, domain_id)

    # Chart data (30 days)
    chart_data = get_pass_fail_over_time(db, org.id, domain_id=domain_id, days=30)

    # Recent reports
    from app.models import DmarcReport
    recent_reports = (
        db.query(DmarcReport)
        .filter_by(organization_id=org.id, domain_id=domain_id)
        .order_by(DmarcReport.created_at.desc())
        .limit(10)
        .all()
    )

    # DMARC record suggestion
    rua_addr = next(
        (a.address for a in addresses if a.status == "active" and a.purpose == "domain_report"),
        None,
    )
    if not rua_addr:
        # Fall back to org-level address
        org_addr = db.query(InboundMailAddress).filter_by(
            organization_id=org.id, status="active", purpose="org_report"
        ).filter(InboundMailAddress.domain_id.is_(None)).first()
        if org_addr:
            rua_addr = org_addr.address

    suggested_record = None
    if rua_addr:
        p = domain.dmarc_policy or "none"
        suggested_record = (
            f'v=DMARC1; p={p}; rua=mailto:{rua_addr}'
        )
        if domain.dmarc_policy_pct and domain.dmarc_policy_pct < 100:
            suggested_record += f'; pct={domain.dmarc_policy_pct}'

    # External DMARC destination verification record
    ext_verify_record = None
    if rua_addr and "@" in rua_addr:
        rua_domain = rua_addr.split("@")[1]
        if rua_domain != domain.name:
            ext_verify_record = f"{domain.name}._report._dmarc.{rua_domain}"

    return templates.TemplateResponse("domains/detail.html", {
        "request": request, "user": user, "org": org, "domain": domain,
        "addresses": addresses, "recommendations": recs,
        "chart_data": chart_data, "recent_reports": recent_reports,
        "suggested_record": suggested_record,
        "ext_verify_record": ext_verify_record,
        "rua_addr": rua_addr,
        "page_title": f"Domain: {domain.name}",
    })


@router.post("/{domain_id}/toggle")
def domain_toggle(
    request: Request,
    domain_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    domain.is_active = not domain.is_active
    log_action(
        db, "domain.toggle", org_id=org.id, user_id=user.id,
        resource_type="domain", resource_id=domain.id,
        new_value={"is_active": domain.is_active},
    )
    db.commit()
    return RedirectResponse(url=f"/domains/{domain_id}", status_code=303)


@router.post("/{domain_id}/add-address")
def domain_add_address(
    request: Request,
    domain_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=org.id).first()
    if not domain:
        raise HTTPException(status_code=404)
    create_domain_address(db, org, domain)
    db.commit()
    return RedirectResponse(url=f"/domains/{domain_id}", status_code=303)
