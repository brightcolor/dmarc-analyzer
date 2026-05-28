import hashlib
import os
import shutil
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user, get_current_org, get_client_ip
from app.models import Domain, ImportJob, Organization, User
from app.services.audit import log_action
from app.services.import_service import process_import_job
from app.templates_config import templates

router = APIRouter(prefix="/upload", tags=["upload"])

MAX_SIZE = settings.UPLOAD_MAX_SIZE
ALLOWED_EXT = settings.allowed_upload_extensions


@router.get("", response_class=HTMLResponse)
def upload_page(
    request: Request,
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    domains = db.query(Domain).filter_by(organization_id=org.id, is_active=True).all()
    return templates.TemplateResponse("upload/index.html", {
        "request": request, "user": user, "org": org,
        "domains": domains, "page_title": "Upload DMARC Report",
    })


@router.post("")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    domain_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org: Organization = Depends(get_current_org),
):
    # Validate extension
    filename = (file.filename or "").lower()
    if not any(filename.endswith(ext) for ext in ALLOWED_EXT):
        raise HTTPException(
            status_code=400,
            detail=f"File type not supported. Allowed: {', '.join(ALLOWED_EXT)}",
        )

    # Read with size limit
    content = await file.read(MAX_SIZE + 1)
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=413, detail="File too large")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Determine file type
    if filename.endswith(".zip"):
        file_type = "zip"
    elif filename.endswith(".xml.gz") or filename.endswith(".gz"):
        file_type = "xml_gz"
    else:
        file_type = "xml"

    # Save to upload dir
    upload_dir = settings.upload_dir_path / org.id
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_hash = hashlib.sha256(content).hexdigest()
    save_path = upload_dir / f"{file_hash[:16]}_{file.filename}"

    with open(save_path, "wb") as fh:
        fh.write(content)

    # Create import job
    job = ImportJob(
        organization_id=org.id,
        domain_id=domain_id if domain_id else None,
        source="web_upload",
        status="pending",
        file_path=str(save_path),
        file_name=file.filename,
        file_size=len(content),
        file_hash=file_hash,
        file_type=file_type,
    )
    db.add(job)
    db.flush()

    # Process synchronously (suitable for small VPS; async worker optional)
    process_import_job(db, job)

    log_action(
        db, "import.upload", org_id=org.id, user_id=user.id,
        resource_type="import_job", resource_id=job.id,
        new_value={"filename": file.filename, "size": len(content)},
        ip_address=get_client_ip(request),
    )
    db.commit()

    return RedirectResponse(url=f"/imports/{job.id}", status_code=303)
