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


class TechVulnerabilitySummary(BaseModel):
    technology_name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    element_id: str
    cve_count: int = 0
    max_cvss: Optional[float] = None
    max_severity: Optional[str] = None
