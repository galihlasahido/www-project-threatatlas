from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import (
    DiagramThreat, DiagramMitigation, Threat, Diagram, Product,
    TechnologyStack, CVE, CVECPE, User as UserModel,
    Pentest, PentestFinding,
)
from app.models.enums import UserRole
from app.auth.dependencies import get_current_user
from app.auth.permissions import require_not_external_pentester
from app.schemas.analytics import (
    AnalyticsSummary,
    RiskHeatmapCell,
    CategoryDistribution,
    StatusDistribution,
    SeverityDistribution,
    TechVulnerabilitySummary,
    PentestAnalyticsSummary,
    VendorComparisonItem,
    RiskMatrixCell,
    RemediationTimelineItem,
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
    require_not_external_pentester(current_user)
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
    require_not_external_pentester(current_user)
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
    require_not_external_pentester(current_user)
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
    require_not_external_pentester(current_user)
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
    require_not_external_pentester(current_user)
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
    require_not_external_pentester(current_user)
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


@router.get("/pentest-summary", response_model=PentestAnalyticsSummary)
def get_pentest_summary(
    product_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get aggregated pentest analytics summary."""
    require_not_external_pentester(current_user)
    from datetime import datetime
    from collections import defaultdict

    # Base query for pentests
    pt_query = db.query(Pentest).join(Product, Pentest.product_id == Product.id)
    if current_user.role != UserRole.ADMIN.value:
        pt_query = pt_query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        pt_query = pt_query.filter(Pentest.product_id == product_id)
    total_pentests = pt_query.count()

    # Base query for findings
    f_query = (
        db.query(PentestFinding)
        .join(Pentest, PentestFinding.pentest_id == Pentest.id)
        .join(Product, Pentest.product_id == Product.id)
    )
    if current_user.role != UserRole.ADMIN.value:
        f_query = f_query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        f_query = f_query.filter(Pentest.product_id == product_id)

    findings = f_query.all()
    total_findings = len(findings)

    by_severity = {}
    by_status = {}
    open_count = 0
    closed_count = 0
    remediation_days = []
    cvss_scores = []
    priority_counts = defaultdict(int)
    risk_matrix_map = defaultdict(int)
    timeline_found = defaultdict(int)
    timeline_fixed = defaultdict(int)

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_status[f.status] = by_status.get(f.status, 0) + 1

        if f.status in ("open", "in_progress"):
            open_count += 1
        else:
            closed_count += 1

        if f.patch_date and f.created_at:
            delta = f.patch_date - f.created_at
            remediation_days.append(delta.total_seconds() / 86400)

        # CVSS scores
        if f.cvss_score is not None:
            cvss_scores.append(f.cvss_score)

        # Priority breakdown
        if f.remediation_priority:
            priority_counts[f.remediation_priority] += 1

        # Risk matrix: likelihood x severity
        if f.likelihood and f.severity:
            risk_matrix_map[(f.likelihood, f.severity)] += 1

        # Remediation timeline by month
        if f.created_at:
            month_key = f.created_at.strftime("%Y-%m")
            timeline_found[month_key] += 1
        if f.patch_date:
            fix_month = f.patch_date.strftime("%Y-%m")
            timeline_fixed[fix_month] += 1

    mean_time_to_remediate = round(sum(remediation_days) / len(remediation_days), 2) if remediation_days else None

    # Health score: 100 - critical*10 - high*5 - medium*2 - low*0.5 for open findings
    open_findings_list = [f for f in findings if f.status in ("open", "in_progress")]
    penalty = 0.0
    for f in open_findings_list:
        if f.severity == "critical":
            penalty += 10
        elif f.severity == "high":
            penalty += 5
        elif f.severity == "medium":
            penalty += 2
        elif f.severity == "low":
            penalty += 0.5
    health_score = max(0.0, min(100.0, 100 - penalty))

    # Build risk matrix list
    risk_matrix = [
        RiskMatrixCell(likelihood=lk, severity=sv, count=cnt)
        for (lk, sv), cnt in risk_matrix_map.items()
    ]

    # Build remediation timeline
    all_months = sorted(set(list(timeline_found.keys()) + list(timeline_fixed.keys())))
    remediation_timeline = [
        RemediationTimelineItem(month=m, found=timeline_found.get(m, 0), fixed=timeline_fixed.get(m, 0))
        for m in all_months
    ]

    # Average CVSS score
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else None

    return PentestAnalyticsSummary(
        total_pentests=total_pentests,
        total_findings=total_findings,
        findings_by_severity=by_severity,
        findings_by_status=by_status,
        open_findings=open_count,
        closed_findings=closed_count,
        mean_time_to_remediate_days=mean_time_to_remediate,
        health_score=round(health_score, 2),
        risk_matrix=risk_matrix,
        remediation_timeline=remediation_timeline,
        priority_breakdown=dict(priority_counts),
        avg_cvss_score=avg_cvss,
    )


@router.get("/vendor-comparison", response_model=list[VendorComparisonItem])
def get_vendor_comparison(
    product_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Compare pentest vendors by finding counts and severity breakdown."""
    require_not_external_pentester(current_user)
    pt_query = db.query(Pentest).join(Product, Pentest.product_id == Product.id)
    if current_user.role != UserRole.ADMIN.value:
        pt_query = pt_query.filter(Product.user_id == current_user.id)
    if product_id is not None:
        pt_query = pt_query.filter(Pentest.product_id == product_id)

    pentests = pt_query.all()

    vendor_map: dict[str, dict] = {}
    for pt in pentests:
        vendor_key = pt.vendor_name or pt.vendor_type or "Unknown"
        if vendor_key not in vendor_map:
            vendor_map[vendor_key] = {
                "vendor_name": vendor_key,
                "vendor_type": pt.vendor_type,
                "pentest_count": 0,
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
        vendor_map[vendor_key]["pentest_count"] += 1

        findings = db.query(PentestFinding).filter(PentestFinding.pentest_id == pt.id).all()
        vendor_map[vendor_key]["total_findings"] += len(findings)
        for f in findings:
            if f.severity in ("critical", "high", "medium", "low"):
                vendor_map[vendor_key][f.severity] += 1

    return [VendorComparisonItem(**v) for v in vendor_map.values()]


@router.get("/tech-vulnerability", response_model=list[TechVulnerabilitySummary])
def get_tech_vulnerability_summary(
    product_id: int | None = None,
    diagram_id: int | None = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get vulnerability summary per technology stack entry."""
    require_not_external_pentester(current_user)
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
