from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import (
    DiagramThreat, DiagramMitigation, Threat, Diagram, Product,
    TechnologyStack, CVE, CVECPE, User as UserModel,
)
from app.models.enums import UserRole
from app.auth.dependencies import get_current_user
from app.schemas.analytics import (
    AnalyticsSummary,
    RiskHeatmapCell,
    CategoryDistribution,
    StatusDistribution,
    SeverityDistribution,
    TechVulnerabilitySummary,
)

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _base_threat_query(db: Session, current_user: UserModel, product_id: int | None, diagram_id: int | None, model_id: int | None):
    """Build a base query on DiagramThreat with ownership and optional filters."""
    query = db.query(DiagramThreat).join(Diagram, DiagramThreat.diagram_id == Diagram.id).join(Product, Diagram.product_id == Product.id)

    # Ownership filter
    if current_user.role != UserRole.ADMIN.value:
        query = query.filter(Product.user_id == current_user.id)

    if product_id is not None:
        query = query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        query = query.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        query = query.filter(DiagramThreat.model_id == model_id)

    return query


def _base_mitigation_query(db: Session, current_user: UserModel, product_id: int | None, diagram_id: int | None, model_id: int | None):
    """Build a base query on DiagramMitigation with ownership and optional filters."""
    query = db.query(DiagramMitigation).join(Diagram, DiagramMitigation.diagram_id == Diagram.id).join(Product, Diagram.product_id == Product.id)

    if current_user.role != UserRole.ADMIN.value:
        query = query.filter(Product.user_id == current_user.id)

    if product_id is not None:
        query = query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        query = query.filter(DiagramMitigation.diagram_id == diagram_id)
    if model_id is not None:
        query = query.filter(DiagramMitigation.model_id == model_id)

    return query


@router.get("/summary", response_model=AnalyticsSummary)
def get_analytics_summary(
    product_id: int | None = None,
    diagram_id: int | None = None,
    model_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get an aggregated analytics summary of threats and mitigations."""
    # Total threats
    threat_q = _base_threat_query(db, current_user, product_id, diagram_id, model_id)
    total_threats = threat_q.count()

    # Total mitigations
    mit_q = _base_mitigation_query(db, current_user, product_id, diagram_id, model_id)
    total_mitigations = mit_q.count()

    # Threats by severity
    severity_rows = (
        db.query(DiagramThreat.severity, func.count(DiagramThreat.id))
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
    )
    if current_user.role != UserRole.ADMIN.value:
        severity_rows = severity_rows.filter(Product.user_id == current_user.id)
    if product_id is not None:
        severity_rows = severity_rows.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        severity_rows = severity_rows.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        severity_rows = severity_rows.filter(DiagramThreat.model_id == model_id)
    severity_rows = severity_rows.group_by(DiagramThreat.severity).all()
    threats_by_severity = {sev or "unknown": cnt for sev, cnt in severity_rows}

    # Threats by status
    status_rows = (
        db.query(DiagramThreat.status, func.count(DiagramThreat.id))
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
    )
    if current_user.role != UserRole.ADMIN.value:
        status_rows = status_rows.filter(Product.user_id == current_user.id)
    if product_id is not None:
        status_rows = status_rows.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        status_rows = status_rows.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        status_rows = status_rows.filter(DiagramThreat.model_id == model_id)
    status_rows = status_rows.group_by(DiagramThreat.status).all()
    threats_by_status = {st or "unknown": cnt for st, cnt in status_rows}

    # Mitigation coverage
    mitigated_count = threats_by_status.get("mitigated", 0)
    mitigation_coverage = (mitigated_count / total_threats * 100.0) if total_threats > 0 else 0.0

    # Average risk score
    avg_row = (
        db.query(func.avg(DiagramThreat.risk_score))
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
    )
    if current_user.role != UserRole.ADMIN.value:
        avg_row = avg_row.filter(Product.user_id == current_user.id)
    if product_id is not None:
        avg_row = avg_row.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        avg_row = avg_row.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        avg_row = avg_row.filter(DiagramThreat.model_id == model_id)
    avg_risk = avg_row.scalar()
    avg_risk_score = round(float(avg_risk), 2) if avg_risk is not None else 0.0

    return AnalyticsSummary(
        total_threats=total_threats,
        total_mitigations=total_mitigations,
        threats_by_severity=threats_by_severity,
        threats_by_status=threats_by_status,
        mitigation_coverage=round(mitigation_coverage, 2),
        avg_risk_score=avg_risk_score,
    )


@router.get("/risk-heatmap", response_model=list[RiskHeatmapCell])
def get_risk_heatmap(
    product_id: int | None = None,
    diagram_id: int | None = None,
    model_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get risk heatmap data grouped by likelihood and impact."""
    query = (
        db.query(
            DiagramThreat.likelihood,
            DiagramThreat.impact,
            func.count(DiagramThreat.id).label("count"),
        )
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
        .filter(DiagramThreat.likelihood.isnot(None), DiagramThreat.impact.isnot(None))
    )

    if current_user.role != UserRole.ADMIN.value:
        query = query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        query = query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        query = query.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        query = query.filter(DiagramThreat.model_id == model_id)

    rows = query.group_by(DiagramThreat.likelihood, DiagramThreat.impact).all()
    return [RiskHeatmapCell(likelihood=r[0], impact=r[1], count=r[2]) for r in rows]


@router.get("/category-distribution", response_model=list[CategoryDistribution])
def get_category_distribution(
    product_id: int | None = None,
    diagram_id: int | None = None,
    model_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get threat distribution by category (from Threat definitions)."""
    query = (
        db.query(Threat.category, func.count(DiagramThreat.id).label("count"))
        .join(Threat, DiagramThreat.threat_id == Threat.id)
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
    )

    if current_user.role != UserRole.ADMIN.value:
        query = query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        query = query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        query = query.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        query = query.filter(DiagramThreat.model_id == model_id)

    rows = query.group_by(Threat.category).all()
    return [CategoryDistribution(category=cat or "Uncategorized", count=cnt) for cat, cnt in rows]


@router.get("/status-distribution", response_model=list[StatusDistribution])
def get_status_distribution(
    product_id: int | None = None,
    diagram_id: int | None = None,
    model_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get threat distribution by status."""
    query = (
        db.query(DiagramThreat.status, func.count(DiagramThreat.id).label("count"))
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
    )

    if current_user.role != UserRole.ADMIN.value:
        query = query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        query = query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        query = query.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        query = query.filter(DiagramThreat.model_id == model_id)

    rows = query.group_by(DiagramThreat.status).all()
    return [StatusDistribution(status=st or "unknown", count=cnt) for st, cnt in rows]


@router.get("/severity-distribution", response_model=list[SeverityDistribution])
def get_severity_distribution(
    product_id: int | None = None,
    diagram_id: int | None = None,
    model_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get threat distribution by severity."""
    query = (
        db.query(DiagramThreat.severity, func.count(DiagramThreat.id).label("count"))
        .join(Diagram, DiagramThreat.diagram_id == Diagram.id)
        .join(Product, Diagram.product_id == Product.id)
    )

    if current_user.role != UserRole.ADMIN.value:
        query = query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        query = query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        query = query.filter(DiagramThreat.diagram_id == diagram_id)
    if model_id is not None:
        query = query.filter(DiagramThreat.model_id == model_id)

    rows = query.group_by(DiagramThreat.severity).all()
    return [SeverityDistribution(severity=sev or "unknown", count=cnt) for sev, cnt in rows]


@router.get("/cve-severity", response_model=list[SeverityDistribution])
def get_cve_severity_distribution(
    product_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get CVE distribution by severity for technologies used in a product's diagrams."""
    # Get tech stacks for the product's diagrams
    tech_query = db.query(TechnologyStack).join(Diagram, TechnologyStack.diagram_id == Diagram.id).join(Product, Diagram.product_id == Product.id)

    if current_user.role != UserRole.ADMIN.value:
        tech_query = tech_query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        tech_query = tech_query.filter(Diagram.product_id == product_id)

    tech_stacks = tech_query.all()

    if not tech_stacks:
        return []

    # Collect product names (lowercase) from tech stacks to match against CVECPE.product
    product_names = set()
    for ts in tech_stacks:
        product_names.add(ts.technology_name.lower())
        if ts.vendor:
            product_names.add(ts.vendor.lower())

    if not product_names:
        return []

    # Find CVEs via CVECPE matching on product name
    cve_query = (
        db.query(CVE.cvss_v3_severity, func.count(CVE.id).label("count"))
        .join(CVECPE, CVECPE.cve_id == CVE.id)
        .filter(func.lower(CVECPE.product).in_(product_names))
        .filter(CVE.cvss_v3_severity.isnot(None))
        .group_by(CVE.cvss_v3_severity)
    )

    rows = cve_query.all()
    return [SeverityDistribution(severity=sev, count=cnt) for sev, cnt in rows]


@router.get("/tech-vulnerability", response_model=list[TechVulnerabilitySummary])
def get_tech_vulnerability_summary(
    product_id: int | None = None,
    diagram_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get vulnerability summary per technology stack entry."""
    tech_query = db.query(TechnologyStack).join(Diagram, TechnologyStack.diagram_id == Diagram.id).join(Product, Diagram.product_id == Product.id)

    if current_user.role != UserRole.ADMIN.value:
        tech_query = tech_query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        tech_query = tech_query.filter(Diagram.product_id == product_id)
    if diagram_id is not None:
        tech_query = tech_query.filter(TechnologyStack.diagram_id == diagram_id)

    tech_stacks = tech_query.all()

    results = []
    for ts in tech_stacks:
        # Match CVEs via CVECPE product name (case-insensitive)
        match_names = [ts.technology_name.lower()]
        if ts.vendor:
            match_names.append(ts.vendor.lower())

        cve_stats = (
            db.query(
                func.count(CVE.id).label("cve_count"),
                func.max(CVE.cvss_v3_score).label("max_cvss"),
                func.max(CVE.cvss_v3_severity).label("max_severity"),
            )
            .join(CVECPE, CVECPE.cve_id == CVE.id)
            .filter(func.lower(CVECPE.product).in_(match_names))
        ).first()

        cve_count = cve_stats[0] if cve_stats[0] else 0
        max_cvss = float(cve_stats[1]) if cve_stats[1] is not None else None
        max_severity = cve_stats[2]

        results.append(
            TechVulnerabilitySummary(
                technology_name=ts.technology_name,
                version=ts.version,
                vendor=ts.vendor,
                element_id=ts.element_id,
                cve_count=cve_count,
                max_cvss=max_cvss,
                max_severity=max_severity,
            )
        )

    return results
