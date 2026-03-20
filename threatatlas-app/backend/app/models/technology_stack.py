from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base

class TechnologyStack(Base):
    __tablename__ = "technology_stacks"

    id = Column(Integer, primary_key=True, index=True)
    diagram_id = Column(Integer, ForeignKey("diagrams.id", ondelete="CASCADE"), nullable=False, index=True)
    element_id = Column(String(100), nullable=False)  # ReactFlow node ID
    technology_name = Column(String(200), nullable=False)  # e.g., "PostgreSQL"
    version = Column(String(100), nullable=True)  # e.g., "16.0"
    vendor = Column(String(200), nullable=True)  # e.g., "postgresql"
    cpe_pattern = Column(String(500), nullable=True)  # auto-generated CPE match string
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    diagram = relationship("Diagram", back_populates="technology_stacks")

    __table_args__ = (UniqueConstraint("diagram_id", "element_id", "technology_name", name="uq_diagram_element_tech"),)
