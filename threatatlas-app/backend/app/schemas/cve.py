from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class CVEBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    source_url: Optional[str] = None
    status: Optional[str] = None

class CVECreate(CVEBase):
    raw_json: Optional[dict] = None

class CVE(CVEBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class CVEWithDetails(CVE):
    cwes: List["CWEBrief"] = []
    cpes: List["CPEBrief"] = []

class CWEBrief(BaseModel):
    id: int
    cwe_id: str
    name: str
    category: Optional[str] = None
    class Config:
        from_attributes = True

class CPEBrief(BaseModel):
    id: int
    cpe_uri: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    class Config:
        from_attributes = True

class CVESearchParams(BaseModel):
    keyword: Optional[str] = None
    cwe_id: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    severity: Optional[str] = None
    fetch_from_nvd: bool = False

class CVESummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
