from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import (
    DiagramThreat, DiagramMitigation, Threat, Mitigation, Diagram, Product,
    Model, TechnologyStack, CVE, CVECPE, CWE, ThreatCWE,
    User as UserModel,
)
from app.models.enums import UserRole
from app.auth.dependencies import get_current_user
from app.schemas.report import (
    ThreatModelReport,
    ExecutiveSummary,
    ReportDiagramSection,
    ReportThreatItem,
    ReportMitigationItem,
    ReportCVEItem,
)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/threat-model", response_model=ThreatModelReport)
def get_threat_model_report(
    product_id: int = Query(..., description="Product ID (required)"),
    diagram_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a full threat model report for a product."""

    # 1. Load product
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with id {product_id} not found",
        )

    # Ownership check
    if current_user.role != UserRole.ADMIN.value and product.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this product",
        )

    # 2. Load diagrams
    diagram_query = db.query(Diagram).filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        diagram_query = diagram_query.filter(Diagram.id == diagram_id)
    diagrams = diagram_query.all()

    # Aggregation counters for executive summary
    total_threats = 0
    critical_threats = 0
    high_threats = 0
    medium_threats = 0
    low_threats = 0
    total_mitigations = 0
    mitigated_count = 0

    diagram_sections = []
    all_tech_stacks = []

    for diag in diagrams:
        # 3a. Load models for this diagram
        models = db.query(Model).filter(Model.diagram_id == diag.id).all()
        model_dicts = [
            {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "framework_id": m.framework_id,
                "status": m.status.value if m.status else None,
            }
            for m in models
        ]

        # 3b. Load threats with joined Threat definition
        dt_rows = (
            db.query(DiagramThreat)
            .options(joinedload(DiagramThreat.threat).joinedload(Threat.cwes))
            .filter(DiagramThreat.diagram_id == diag.id)
            .all()
        )

        threat_items = []
        for dt in dt_rows:
            total_threats += 1
            sev = (dt.severity or "").lower()
            if sev == "critical":
                critical_threats += 1
            elif sev == "high":
                high_threats += 1
            elif sev == "medium":
                medium_threats += 1
            elif sev == "low":
                low_threats += 1

            if (dt.status or "").lower() == "mitigated":
                mitigated_count += 1

            # CWE IDs from the Threat definition's linked CWEs
            cwe_ids = []
            if dt.threat and dt.threat.cwes:
                cwe_ids = [cwe.cwe_id for cwe in dt.threat.cwes]

            # Mitigations linked to this diagram threat
            linked_mits = (
                db.query(DiagramMitigation)
                .options(joinedload(DiagramMitigation.mitigation))
                .filter(DiagramMitigation.threat_id == dt.id)
                .all()
            )
            mit_dicts = [
                {
                    "id": lm.id,
                    "mitigation_name": lm.mitigation.name if lm.mitigation else "Unknown",
                    "status": lm.status,
                    "notes": lm.notes,
                }
                for lm in linked_mits
            ]

            threat_items.append(
                ReportThreatItem(
                    id=dt.id,
                    threat_name=dt.threat.name if dt.threat else "Unknown",
                    category=dt.threat.category if dt.threat else None,
                    element_id=dt.element_id,
                    element_type=dt.element_type,
                    status=dt.status,
                    likelihood=dt.likelihood,
                    impact=dt.impact,
                    risk_score=dt.risk_score,
                    severity=dt.severity,
                    notes=dt.notes,
                    cwes=cwe_ids,
                    mitigations=mit_dicts,
                )
            )

        # 3c. Load all mitigations for this diagram
        dm_rows = (
            db.query(DiagramMitigation)
            .options(joinedload(DiagramMitigation.mitigation))
            .filter(DiagramMitigation.diagram_id == diag.id)
            .all()
        )
        total_mitigations += len(dm_rows)

        mitigation_items = [
            ReportMitigationItem(
                id=dm.id,
                mitigation_name=dm.mitigation.name if dm.mitigation else "Unknown",
                category=dm.mitigation.category if dm.mitigation else None,
                element_id=dm.element_id,
                status=dm.status,
                notes=dm.notes,
            )
            for dm in dm_rows
        ]

        # 3d. Technology stacks
        tech_rows = db.query(TechnologyStack).filter(TechnologyStack.diagram_id == diag.id).all()
        all_tech_stacks.extend(tech_rows)

        tech_dicts = [
            {
                "id": t.id,
                "element_id": t.element_id,
                "technology_name": t.technology_name,
                "version": t.version,
                "vendor": t.vendor,
            }
            for t in tech_rows
        ]

        diagram_sections.append(
            ReportDiagramSection(
                diagram_id=diag.id,
                diagram_name=diag.name,
                description=diag.description,
                models=model_dicts,
                threats=threat_items,
                mitigations=mitigation_items,
                technology_stacks=tech_dicts,
            )
        )

    # 6. Mitigation coverage
    mitigation_coverage = (mitigated_count / total_threats * 100.0) if total_threats > 0 else 0.0

    # 7. Load CVEs matching tech stacks
    product_names = set()
    for ts in all_tech_stacks:
        product_names.add(ts.technology_name.lower())
        if ts.vendor:
            product_names.add(ts.vendor.lower())

    cve_items = []
    if product_names:
        cve_rows = (
            db.query(CVE, CVECPE.product)
            .join(CVECPE, CVECPE.cve_id == CVE.id)
            .filter(CVECPE.product.isnot(None))
            .filter(func_lower_in(db, CVECPE.product, product_names))
            .all()
        )
        # Build a mapping of tech name -> element_id for context
        tech_element_map = {}
        for ts in all_tech_stacks:
            tech_element_map[ts.technology_name.lower()] = ts.element_id
            if ts.vendor:
                tech_element_map[ts.vendor.lower()] = ts.element_id

        seen_cve_ids = set()
        for cve, cpe_product in cve_rows:
            if cve.cve_id in seen_cve_ids:
                continue
            seen_cve_ids.add(cve.cve_id)
            element_id = tech_element_map.get((cpe_product or "").lower())
            cve_items.append(
                ReportCVEItem(
                    cve_id=cve.cve_id,
                    cvss_v3_score=cve.cvss_v3_score,
                    cvss_v3_severity=cve.cvss_v3_severity,
                    description=cve.description,
                    technology=cpe_product,
                    element_id=element_id,
                )
            )

    # 8. Determine overall risk rating
    if critical_threats > 0:
        risk_rating = "Critical"
    elif high_threats > 0:
        risk_rating = "High"
    elif medium_threats > 0:
        risk_rating = "Medium"
    elif low_threats > 0:
        risk_rating = "Low"
    else:
        risk_rating = "Unknown"

    executive_summary = ExecutiveSummary(
        total_threats=total_threats,
        critical_threats=critical_threats,
        high_threats=high_threats,
        medium_threats=medium_threats,
        low_threats=low_threats,
        total_mitigations=total_mitigations,
        mitigation_coverage=round(mitigation_coverage, 2),
        total_cves=len(cve_items),
        risk_rating=risk_rating,
    )

    return ThreatModelReport(
        generated_at=datetime.now(timezone.utc),
        product_name=product.name,
        product_description=product.description,
        product_id=product.id,
        executive_summary=executive_summary,
        diagrams=diagram_sections,
        cves=cve_items,
    )


def func_lower_in(db: Session, column, values: set):
    """Helper to create a case-insensitive IN filter."""
    from sqlalchemy import func
    return func.lower(column).in_(values)
