from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from typing import Optional

from app.database import get_db
from app.models import User as UserModel, Diagram as DiagramModel
from app.models.technology_stack import TechnologyStack as TechnologyStackModel
from app.schemas.technology_stack import (
    TechnologyStack as TechnologyStackSchema,
    TechnologyStackCreate,
    TechnologyStackUpdate,
)
from app.schemas.cve import CVE as CVESchema
from app.auth.dependencies import get_current_user
from app.auth.permissions import require_standard_or_admin, require_resource_access
from app.models.enums import UserRole
from app.services.cve_service import cve_service

router = APIRouter(tags=["technology-stacks"])


def _generate_cpe_pattern(vendor: Optional[str], product: str) -> str:
    """Auto-generate CPE pattern from vendor and product."""
    v = vendor.lower() if vendor else "*"
    p = product.lower()
    return f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:*:*:*"


@router.get(
    "/diagrams/{diagram_id}/technology-stacks",
    response_model=list[TechnologyStackSchema],
)
def list_technology_stacks_for_diagram(
    diagram_id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all technology stacks for a diagram."""
    diagram = (
        db.query(DiagramModel)
        .options(joinedload(DiagramModel.product))
        .filter(DiagramModel.id == diagram_id)
        .first()
    )
    if not diagram:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Diagram with id {diagram_id} not found",
        )

    return (
        db.query(TechnologyStackModel)
        .filter(TechnologyStackModel.diagram_id == diagram_id)
        .all()
    )


@router.get(
    "/diagrams/{diagram_id}/elements/{element_id}/technology-stacks",
    response_model=list[TechnologyStackSchema],
)
def list_technology_stacks_for_element(
    diagram_id: int,
    element_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List technology stacks for a specific element in a diagram."""
    return (
        db.query(TechnologyStackModel)
        .filter(
            TechnologyStackModel.diagram_id == diagram_id,
            TechnologyStackModel.element_id == element_id,
        )
        .all()
    )


@router.post(
    "/diagrams/{diagram_id}/technology-stacks",
    response_model=TechnologyStackSchema,
    status_code=status.HTTP_201_CREATED,
)
def create_technology_stack(
    diagram_id: int,
    tech_stack: TechnologyStackCreate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a technology tag to a diagram element."""
    require_standard_or_admin(current_user)

    diagram = (
        db.query(DiagramModel)
        .options(joinedload(DiagramModel.product))
        .filter(DiagramModel.id == diagram_id)
        .first()
    )
    if not diagram:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Diagram with id {diagram_id} not found",
        )

    require_resource_access(current_user, diagram.product.user_id)

    # Check for duplicate
    existing = (
        db.query(TechnologyStackModel)
        .filter(
            TechnologyStackModel.diagram_id == diagram_id,
            TechnologyStackModel.element_id == tech_stack.element_id,
            TechnologyStackModel.technology_name == tech_stack.technology_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This technology is already tagged on this element",
        )

    cpe_pattern = _generate_cpe_pattern(tech_stack.vendor, tech_stack.technology_name)

    db_tech = TechnologyStackModel(
        diagram_id=diagram_id,
        element_id=tech_stack.element_id,
        technology_name=tech_stack.technology_name,
        version=tech_stack.version,
        vendor=tech_stack.vendor,
        cpe_pattern=cpe_pattern,
    )
    db.add(db_tech)
    db.commit()
    db.refresh(db_tech)
    return db_tech


@router.put("/technology-stacks/{id}", response_model=TechnologyStackSchema)
def update_technology_stack(
    id: int,
    tech_stack: TechnologyStackUpdate,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a technology stack entry."""
    require_standard_or_admin(current_user)

    db_tech = (
        db.query(TechnologyStackModel)
        .options(
            joinedload(TechnologyStackModel.diagram).joinedload(DiagramModel.product)
        )
        .filter(TechnologyStackModel.id == id)
        .first()
    )
    if not db_tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TechnologyStack with id {id} not found",
        )

    require_resource_access(current_user, db_tech.diagram.product.user_id)

    update_data = tech_stack.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_tech, field, value)

    # Regenerate CPE pattern
    vendor = update_data.get("vendor", db_tech.vendor)
    tech_name = update_data.get("technology_name", db_tech.technology_name)
    db_tech.cpe_pattern = _generate_cpe_pattern(vendor, tech_name)

    db.commit()
    db.refresh(db_tech)
    return db_tech


@router.delete("/technology-stacks/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_technology_stack(
    id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a technology stack entry."""
    require_standard_or_admin(current_user)

    db_tech = (
        db.query(TechnologyStackModel)
        .options(
            joinedload(TechnologyStackModel.diagram).joinedload(DiagramModel.product)
        )
        .filter(TechnologyStackModel.id == id)
        .first()
    )
    if not db_tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TechnologyStack with id {id} not found",
        )

    require_resource_access(current_user, db_tech.diagram.product.user_id)

    db.delete(db_tech)
    db.commit()
    return None


@router.get("/technology-stacks/{id}/cves", response_model=list[CVESchema])
def get_cves_for_technology_stack(
    id: int,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get matched CVEs for a specific technology stack entry."""
    db_tech = (
        db.query(TechnologyStackModel)
        .filter(TechnologyStackModel.id == id)
        .first()
    )
    if not db_tech:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TechnologyStack with id {id} not found",
        )

    return cve_service.get_local_cves(
        db,
        vendor=db_tech.vendor,
        product=db_tech.technology_name,
    )
