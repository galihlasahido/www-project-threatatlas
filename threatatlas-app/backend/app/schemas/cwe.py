from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class CWEBase(BaseModel):
    cwe_id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    url: Optional[str] = None

class CWECreate(CWEBase):
    pass

class CWE(CWEBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class CWEWithCVECount(CWE):
    cve_count: int = 0
    threat_count: int = 0
