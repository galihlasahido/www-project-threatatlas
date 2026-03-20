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
