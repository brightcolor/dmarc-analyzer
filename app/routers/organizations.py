import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_client_ip, get_current_org, get_current_user
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

    return templates.TemplateResponse("organizations/index.html", {
        "request": request, "user": user, "orgs": orgs, "page_title": "Organizations",
    })


@router.get("/new", response_class=HTMLResponse)
def org_new_form(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("organizations/form.html", {
        "request": request, "user": user, "org_obj": None, "page_title": "New Organization",
    })


@router.post("/new")
def org_create(
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    slug = slug.strip().lower()
    if not SLUG_RE.match(slug):
        return templates.TemplateResponse("organizations/form.html", {
            "request": request, "user": user, "org_obj": None,
            "error": "Slug must be lowercase alphanumeric with hyphens (2-80 chars).",
            "page_title": "New Organization",
        })

    if db.query(Organization).filter_by(slug=slug).first():
        return templates.TemplateResponse("organizations/form.html", {
            "request": request, "user": user, "org_obj": None,
            "error": "Slug already in use.", "page_title": "New Organization",
        })

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
    return templates.TemplateResponse("auth/select_org.html", {
        "request": request, "user": user, "orgs": orgs, "page_title": "Select Organization",
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

    return templates.TemplateResponse("organizations/detail.html", {
        "request": request, "user": user, "org": current_org,
        "org_detail": org, "memberships": memberships,
        "page_title": f"Organization: {org.name}",
    })
