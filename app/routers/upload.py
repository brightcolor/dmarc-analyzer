import hashlib

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_client_ip, get_current_org, get_current_user
from app.models import Domain, ImportJob, Organization, User
from app.services.alert_service import evaluate_after_import
from app.services.audit import log_action
from app.services.files import safe_filename
from app.services.import_service import process_import_job
from app.templates_config import _filesizeformat, templates

router = APIRouter(prefix="/upload", tags=["upload"])


def _page(request: Request, user: User, org: Organization, db: Session, error: str | None = None,
          status_code: int = 200):
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).order_by(Domain.name).all()
    return templates.TemplateResponse(request, "upload/index.html", {
        "user": user, "org": org, "domains": domains, "error": error,
        "extensions": sorted(settings.allowed_upload_extensions),
        "max_size": _filesizeformat(settings.UPLOAD_MAX_SIZE),
        "page_title": "Bericht hochladen",
    }, status_code=status_code)


@router.get("", response_class=HTMLResponse)
def upload_page(
    request: Request,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    return _page(request, user, org, db)


@router.post("")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    domain_id: str | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    original_name = file.filename or ""
    lower = original_name.lower()
    allowed = sorted(settings.allowed_upload_extensions)
    if not any(lower.endswith(ext) for ext in allowed):
        return _page(request, user, org, db, "Diese Dateiart kann die Anwendung nicht lesen. Erlaubt sind "
                     f"{', '.join(allowed)}. Wähle eine Berichtsdatei aus der Mail des Empfängers.", 400)

    content = await file.read(settings.UPLOAD_MAX_SIZE + 1)
    if len(content) > settings.UPLOAD_MAX_SIZE:
        return _page(request, user, org, db, "Die Datei ist größer als "
                     f"{_filesizeformat(settings.UPLOAD_MAX_SIZE)}. Lade die Berichte einzeln oder in "
                     "kleineren Archiven hoch.", 413)
    if not content:
        return _page(request, user, org, db, "Die Datei ist leer. Wähle die Berichtsdatei erneut aus.", 400)

    if domain_id and not db.query(Domain.id).filter_by(id=domain_id, organization_id=org.id).first():
        return _page(request, user, org, db, "Die gewählte Domain gehört nicht zu dieser Organisation. Wähle "
                     "eine Domain aus der Liste oder lass die Auswahl leer.", 400)

    if lower.endswith(".zip"):
        file_type = "zip"
    elif lower.endswith(".gz"):
        file_type = "xml_gz"
    else:
        file_type = "xml"

    upload_dir = settings.upload_dir_path / org.id
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_hash = hashlib.sha256(content).hexdigest()
    save_path = upload_dir / f"{file_hash[:16]}_{safe_filename(original_name)}"
    save_path.write_bytes(content)

    job = ImportJob(
        organization_id=org.id,
        domain_id=domain_id or None,
        source="web_upload",
        status="pending",
        file_path=str(save_path),
        file_name=original_name[:500],
        file_size=len(content),
        file_hash=file_hash,
        file_type=file_type,
    )
    db.add(job)
    db.flush()

    # Processed right away; a small server needs no separate worker
    process_import_job(db, job)
    evaluate_after_import(db, org.id)

    log_action(
        db, "import.upload", org_id=org.id, user_id=user.id,
        resource_type="import_job", resource_id=job.id,
        new_value={"filename": original_name, "size": len(content)},
        ip_address=get_client_ip(request),
    )
    db.commit()
    return RedirectResponse(url=f"/imports/{job.id}", status_code=303)
