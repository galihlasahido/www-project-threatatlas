from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class CWE(Base):
    __tablename__ = "cwes"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String(20), unique=True, nullable=False, index=True)  # e.g., "CWE-89"
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(200), nullable=True)  # e.g., "Injection"
    severity = Column(String(20), nullable=True)  # high, medium, low
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    threats = relationship("Threat", secondary="threat_cwes", back_populates="cwes")
    cves = relationship("CVE", secondary="cve_cwes", back_populates="cwes")

class ThreatCWE(Base):
    __tablename__ = "threat_cwes"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    cwe_id = Column(Integer, ForeignKey("cwes.id", ondelete="CASCADE"), nullable=False)

    __table_args__ = (UniqueConstraint("threat_id", "cwe_id", name="uq_threat_cwe"),)
