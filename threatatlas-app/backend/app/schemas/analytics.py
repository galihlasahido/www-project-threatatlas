from pydantic import BaseModel
from typing import Optional, List


class AnalyticsSummary(BaseModel):
    total_threats: int = 0
    total_mitigations: int = 0
    threats_by_severity: dict = {}  # {"critical": N, "high": N, ...}
    threats_by_status: dict = {}  # {"identified": N, "mitigated": N, ...}
    mitigation_coverage: float = 0.0  # percentage
    avg_risk_score: float = 0.0


class RiskHeatmapCell(BaseModel):
    likelihood: int
    impact: int
    count: int


class CategoryDistribution(BaseModel):
    category: str
    count: int


class StatusDistribution(BaseModel):
    status: str
    count: int


class SeverityDistribution(BaseModel):
    severity: str
    count: int


class RiskMatrixCell(BaseModel):
    likelihood: int
    severity: str
    count: int


class RemediationTimelineItem(BaseModel):
    month: str
    found: int
    fixed: int


class PentestAnalyticsSummary(BaseModel):
    total_pentests: int = 0
    total_findings: int = 0
    findings_by_severity: dict = {}  # {"critical": N, "high": N, ...}
    findings_by_status: dict = {}  # {"open": N, "patched": N, ...}
    open_findings: int = 0
    closed_findings: int = 0
    mean_time_to_remediate_days: Optional[float] = None
    health_score: float = 100.0  # 0-100
    risk_matrix: List[RiskMatrixCell] = []
    remediation_timeline: List[RemediationTimelineItem] = []
    priority_breakdown: dict = {}  # {"immediate": N, "short_term": N, ...}
    avg_cvss_score: Optional[float] = None


class VendorComparisonItem(BaseModel):
    vendor_name: str
    vendor_type: Optional[str] = None
    pentest_count: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TechVulnerabilitySummary(BaseModel):
    technology_name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    element_id: str
    cve_count: int = 0
    max_cvss: Optional[float] = None
    max_severity: Optional[str] = None
