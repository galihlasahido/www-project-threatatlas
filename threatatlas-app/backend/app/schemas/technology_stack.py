from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class TechnologyStackBase(BaseModel):
    element_id: str
    technology_name: str
    version: Optional[str] = None
    vendor: Optional[str] = None

class TechnologyStackCreate(TechnologyStackBase):
    diagram_id: int

class TechnologyStackUpdate(BaseModel):
    technology_name: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None

class TechnologyStack(TechnologyStackBase):
    id: int
    diagram_id: int
    cpe_pattern: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class TechnologyStackWithCVEs(TechnologyStack):
    cve_count: int = 0
