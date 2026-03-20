from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, UniqueConstraint, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)  # e.g., "CVE-2024-1234"
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_vector = Column(String(200), nullable=True)
    cvss_v3_severity = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    published_date = Column(DateTime(timezone=True), nullable=True)
    last_modified_date = Column(DateTime(timezone=True), nullable=True)
    source_url = Column(String(500), nullable=True)
    status = Column(String(50), nullable=True)  # Analyzed, Modified, etc.
    raw_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    cwes = relationship("CWE", secondary="cve_cwes", back_populates="cves")
    cpes = relationship("CVECPE", back_populates="cve", cascade="all, delete-orphan")

class CVECWE(Base):
    __tablename__ = "cve_cwes"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    cwe_id = Column(Integer, ForeignKey("cwes.id", ondelete="CASCADE"), nullable=False)

    __table_args__ = (UniqueConstraint("cve_id", "cwe_id", name="uq_cve_cwe"),)

class CVECPE(Base):
    __tablename__ = "cve_cpes"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id", ondelete="CASCADE"), nullable=False)
    cpe_uri = Column(String(500), nullable=False)
    vendor = Column(String(200), nullable=True, index=True)
    product = Column(String(200), nullable=True, index=True)
    version = Column(String(100), nullable=True)

    cve = relationship("CVE", back_populates="cpes")

    __table_args__ = (UniqueConstraint("cve_id", "cpe_uri", name="uq_cve_cpe"),)
