from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime


class ReportThreatItem(BaseModel):
    id: int
    threat_name: str
    category: Optional[str] = None
    element_id: str
    element_type: str
    status: str
    likelihood: Optional[int] = None
    impact: Optional[int] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    notes: Optional[str] = None
    cwes: List[str] = []  # list of CWE IDs like ["CWE-89"]
    mitigations: List[dict] = []


class ReportMitigationItem(BaseModel):
    id: int
    mitigation_name: str
    category: Optional[str] = None
    element_id: str
    status: str
    notes: Optional[str] = None


class ReportDiagramSection(BaseModel):
    diagram_id: int
    diagram_name: str
    description: Optional[str] = None
    models: List[dict] = []
    threats: List[ReportThreatItem] = []
    mitigations: List[ReportMitigationItem] = []
    technology_stacks: List[dict] = []


class ReportCVEItem(BaseModel):
    cve_id: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    description: Optional[str] = None
    technology: Optional[str] = None
    element_id: Optional[str] = None


class ExecutiveSummary(BaseModel):
    total_threats: int = 0
    critical_threats: int = 0
    high_threats: int = 0
    medium_threats: int = 0
    low_threats: int = 0
    total_mitigations: int = 0
    mitigation_coverage: float = 0.0
    total_cves: int = 0
    risk_rating: str = "Unknown"  # Overall: Critical/High/Medium/Low


class ThreatModelReport(BaseModel):
    generated_at: datetime
    product_name: str
    product_description: Optional[str] = None
    product_id: int
    executive_summary: ExecutiveSummary
    diagrams: List[ReportDiagramSection] = []
    cves: List[ReportCVEItem] = []


# ── Pentest Report schemas ───────────────────────────────────────────────────

class ReportRetestSummary(BaseModel):
    total_retests: int = 0
    latest_result: Optional[str] = None
    latest_tested_at: Optional[datetime] = None


class ReportPentestFinding(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    category: Optional[str] = None
    status: str
    affected_element: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    recommendation: Optional[str] = None
    likelihood: Optional[int] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    risk_score: Optional[float] = None
    remediation_priority: Optional[str] = None
    due_date: Optional[datetime] = None
    assigned_to: Optional[str] = None
    evidence_count: int = 0
    retest_summary: Optional[ReportRetestSummary] = None
    cwes: List[str] = []  # CWE-IDs like ["CWE-89"]
    cves: List[str] = []  # CVE-IDs like ["CVE-2024-1234"]
    latest_retest_result: Optional[str] = None  # pass / fail / partial


class ReportPentestSection(BaseModel):
    pentest_id: int
    pentest_name: str
    vendor_name: Optional[str] = None
    vendor_type: Optional[str] = None
    tester_name: Optional[str] = None
    scope: Optional[str] = None
    scope_exclusions: Optional[str] = None
    tools_used: Optional[str] = None
    methodology: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings: List[ReportPentestFinding] = []


class PentestReport(BaseModel):
    generated_at: datetime
    product_name: str
    product_id: int
    total_pentests: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    open_findings: int = 0
    risk_rating: str = "None"
    pentests: List[ReportPentestSection] = []
