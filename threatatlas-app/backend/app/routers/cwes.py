from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.models import User as UserModel, Threat as ThreatModel, CWE as CWEModel
from app.schemas.cwe import CWE as CWESchema, CWEWithCVECount
from app.schemas.cve import CVE as CVESchema
from app.auth.dependencies import get_current_user
from app.auth.permissions import require_not_external_pentester
from app.services.cwe_service import cwe_service

router = APIRouter(prefix="/cwes", tags=["cwes"])


@router.get("/", response_model=list[CWESchema])
def list_cwes(
    search: Optional[str] = None,
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all CWEs with optional search and category filter."""
    require_not_external_pentester(current_user)
    query = db.query(CWEModel)

    if search:
        query = query.filter(
            CWEModel.name.ilike(f"%{search}%")
            | CWEModel.cwe_id.ilike(f"%{search}%")
            | CWEModel.description.ilike(f"%{search}%")
        )
    if category:
        query = query.filter(CWEModel.category == category)

    return query.offset(skip).limit(limit).all()


@router.get("/{cwe_id}", response_model=CWESchema)
def get_cwe(
    cwe_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a single CWE by database ID."""
    require_not_external_pentester(current_user)
    cwe = db.query(CWEModel).filter(CWEModel.id == cwe_id).first()
    if not cwe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CWE with id {cwe_id} not found",
        )
    return cwe


@router.get("/{cwe_id}/cves", response_model=list[CVESchema])
def get_cves_for_cwe(
    cwe_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get CVEs related to a CWE."""
    require_not_external_pentester(current_user)
    cwe = db.query(CWEModel).filter(CWEModel.id == cwe_id).first()
    if not cwe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CWE with id {cwe_id} not found",
        )
    return cwe_service.get_cves_for_cwe(db, cwe_id)


# Threat-CWE linkage endpoints under /threats prefix
threat_cwe_router = APIRouter(prefix="/threats", tags=["threat-cwes"])


@threat_cwe_router.get("/{threat_id}/cwes", response_model=list[CWESchema])
def get_cwes_for_threat(
    threat_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get CWEs linked to a threat."""
    require_not_external_pentester(current_user)
    threat = db.query(ThreatModel).filter(ThreatModel.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with id {threat_id} not found",
        )
    return cwe_service.get_cwes_for_threat(db, threat_id)


@threat_cwe_router.post("/{threat_id}/cwes", status_code=status.HTTP_201_CREATED)
def link_cwe_to_threat(
    threat_id: int,
    body: dict,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Link a CWE to a threat."""
    from app.auth.permissions import require_standard_or_admin

    require_standard_or_admin(current_user)

    threat = db.query(ThreatModel).filter(ThreatModel.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat with id {threat_id} not found",
        )

    cwe_db_id = body.get("cwe_id")
    if not cwe_db_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cwe_id is required",
        )

    cwe = db.query(CWEModel).filter(CWEModel.id == cwe_db_id).first()
    if not cwe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CWE with id {cwe_db_id} not found",
        )

    link = cwe_service.link_cwe_to_threat(db, threat_id, cwe_db_id)
    return {"threat_id": threat_id, "cwe_id": cwe_db_id, "id": link.id}


@threat_cwe_router.delete(
    "/{threat_id}/cwes/{cwe_db_id}", status_code=status.HTTP_204_NO_CONTENT
)
def unlink_cwe_from_threat(
    threat_id: int,
    cwe_db_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Unlink a CWE from a threat."""
    from app.auth.permissions import require_standard_or_admin

    require_standard_or_admin(current_user)

    removed = cwe_service.unlink_cwe_from_threat(db, threat_id, cwe_db_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CWE-Threat link not found",
        )
    return None
