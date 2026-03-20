from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, List

from app.database import get_db
from app.models import User as UserModel
from app.schemas.cve import CVE as CVESchema, CVEWithDetails, CVESearchParams, CVESummary
from app.auth.dependencies import get_current_user
from app.auth.permissions import require_not_external_pentester
from app.services.cve_service import cve_service

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("/summary", response_model=CVESummary)
def get_vulnerability_summary(
    product_ids: Optional[str] = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get vulnerability summary for dashboard. Pass product_ids as comma-separated string."""
    require_not_external_pentester(current_user)
    parsed_ids = None
    if product_ids:
        try:
            parsed_ids = [int(pid.strip()) for pid in product_ids.split(",") if pid.strip()]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="product_ids must be comma-separated integers",
            )

    summary = cve_service.get_vulnerability_summary(db, product_ids=parsed_ids)
    return CVESummary(
        total=summary["total"],
        critical=summary["critical"],
        high=summary["high"],
        medium=summary["medium"],
        low=summary["low"],
    )


@router.get("/by-technology", response_model=list[CVESchema])
def get_cves_by_technology(
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    version: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get CVEs by vendor/product/version from local cache."""
    require_not_external_pentester(current_user)
    if not product:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="product query parameter is required",
        )
    return cve_service.get_local_cves(
        db, vendor=vendor, product=product, limit=limit, offset=offset
    )


@router.get("/", response_model=list[CVESchema])
def list_cves(
    keyword: Optional[str] = None,
    cwe_id: Optional[str] = None,
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List local CVEs with optional filters."""
    require_not_external_pentester(current_user)
    return cve_service.get_local_cves(
        db,
        keyword=keyword,
        cwe_id=cwe_id,
        severity=severity,
        vendor=vendor,
        product=product,
        limit=limit,
        offset=offset,
    )


@router.get("/{cve_id_str}", response_model=CVESchema)
def get_cve(
    cve_id_str: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get CVE by CVE ID string (e.g., CVE-2024-1234). Fetches from NVD if not cached."""
    require_not_external_pentester(current_user)
    cve = cve_service.sync_cve(db, cve_id_str)
    if not cve:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE {cve_id_str} not found",
        )
    return cve


@router.post("/search", response_model=list[CVESchema])
def search_cves(
    params: CVESearchParams,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Search CVEs. If fetch_from_nvd is True, queries NVD API and caches results."""
    require_not_external_pentester(current_user)
    if params.fetch_from_nvd:
        return cve_service.search_and_cache(
            db,
            keyword=params.keyword,
            cwe_id=params.cwe_id,
            vendor=params.vendor,
            product=params.product,
            version=params.version,
        )
    return cve_service.get_local_cves(
        db,
        keyword=params.keyword,
        cwe_id=params.cwe_id,
        severity=params.severity,
        vendor=params.vendor,
        product=params.product,
    )


# Diagram and product CVE endpoints
diagram_cve_router = APIRouter(tags=["diagram-cves"])


@diagram_cve_router.get("/diagrams/{diagram_id}/cves")
def get_diagram_cves(
    diagram_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all CVEs for a diagram's technology stack."""
    require_not_external_pentester(current_user)
    results = cve_service.get_cves_for_diagram(db, diagram_id)
    return [
        {
            "cve": CVESchema.model_validate(item["cve"]),
            "technology": item["technology"],
            "version": item["version"],
            "element_id": item["element_id"],
        }
        for item in results
    ]


@diagram_cve_router.get("/products/{product_id}/cves")
def get_product_cves(
    product_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all CVEs for a product across all its diagrams."""
    require_not_external_pentester(current_user)
    results = cve_service.get_cves_for_product(db, product_id)
    return [
        {
            "cve": CVESchema.model_validate(item["cve"]),
            "technology": item["technology"],
            "version": item["version"],
            "element_id": item["element_id"],
            "diagram_id": item.get("diagram_id"),
            "diagram_name": item.get("diagram_name"),
        }
        for item in results
    ]
