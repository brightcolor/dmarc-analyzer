import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_client_ip, get_current_org, get_current_superadmin, get_current_user
from app.models import Organization, OrganizationMembership, User
from app.services.audit import log_action
from app.services.inbound_address import create_org_address
from app.templates_config import templates

router = APIRouter(prefix="/organizations", tags=["organizations"])

SLUG_RE = re.compile(r"^[a-z0-9-]{2,80}$")


@router.get("", response_class=HTMLResponse)
def org_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if user.is_superadmin:
        orgs = db.query(Organization).order_by(Organization.name).all()
    else:
        from app.services.auth import get_user_orgs
        orgs = get_user_orgs(db, user.id)

    current_id = request.session.get("org_id")
    current = db.query(Organization).filter_by(id=current_id).first() if current_id else None
    return templates.TemplateResponse(request, "organizations/index.html", {
        "user": user, "org": current, "orgs": orgs, "page_title": "Organisationen",
    })


def _org_form(request: Request, user: User, values: dict | None = None, error: str | None = None,
              status_code: int = 200):
    return templates.TemplateResponse(request, "organizations/form.html", {
        "user": user, "values": values or {}, "error": error, "page_title": "Organisation anlegen",
    }, status_code=status_code)


@router.get("/new", response_class=HTMLResponse)
def org_new_form(request: Request, user: User = Depends(get_current_superadmin)):
    return _org_form(request, user)


@router.post("/new")
def org_create(
    request: Request,
    name: str = Form(""),
    slug: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_superadmin),
):
    values = {"name": name, "slug": slug}
    slug = slug.strip().lower()
    if not name.strip():
        return _org_form(request, user, values, "Gib der Organisation einen Namen.", 400)
    if not SLUG_RE.match(slug):
        return _org_form(request, user, values, "Die Kennung darf nur Kleinbuchstaben, Ziffern und Bindestriche "
                         "enthalten und muss 2 bis 80 Zeichen lang sein, etwa muster-farben.", 400)
    if db.query(Organization).filter_by(slug=slug).first():
        return _org_form(request, user, values, f"Die Kennung {slug} ist schon vergeben. Wähle eine andere.", 400)

    org = Organization(name=name.strip(), slug=slug, owner_id=user.id, is_active=True)
    db.add(org)
    db.flush()

    # Add creator as org_admin
    membership = OrganizationMembership(
        user_id=user.id,
        organization_id=org.id,
        role="org_admin",
    )
    db.add(membership)
    db.flush()

    # Auto-create org-level inbound address
    create_org_address(db, org)

    log_action(
        db, "org.create", org_id=org.id, user_id=user.id,
        resource_type="organization", resource_id=org.id,
        new_value={"name": name, "slug": slug},
        ip_address=get_client_ip(request),
    )
    db.commit()
    request.session["org_id"] = org.id
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/select", response_class=HTMLResponse)
def select_org_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.services.auth import get_user_orgs
    orgs = get_user_orgs(db, user.id) if not user.is_superadmin else \
        db.query(Organization).filter_by(is_active=True).all()
    current_id = request.session.get("org_id")
    current = db.query(Organization).filter_by(id=current_id).first() if current_id else None
    return templates.TemplateResponse(request, "auth/select_org.html", {
        "user": user, "org": current, "orgs": orgs, "page_title": "Organisation wählen",
    })


@router.post("/select")
def select_org(
    request: Request,
    org_id: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.services.auth import can_access_org
    if not can_access_org(db, user, org_id):
        raise HTTPException(status_code=403)
    request.session["org_id"] = org_id
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/{org_id}", response_class=HTMLResponse)
def org_detail(
    request: Request,
    org_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    current_org: Organization = Depends(get_current_org),
):
    from app.services.auth import can_access_org
    if not can_access_org(db, user, org_id):
        raise HTTPException(status_code=403)
    org = db.query(Organization).filter_by(id=org_id).first()
    if not org:
        raise HTTPException(status_code=404)

    memberships = db.query(OrganizationMembership).filter_by(organization_id=org_id).all()

    return templates.TemplateResponse(request, "organizations/detail.html", {
        "user": user, "org": current_org,
        "org_detail": org, "memberships": memberships,
        "page_title": org.name,
    })
