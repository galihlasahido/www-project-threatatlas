from typing import List
from sqlalchemy.orm import Session

from app.models.cwe import CWE, ThreatCWE
from app.models.cve import CVE, CVECWE


class CWEService:

    @staticmethod
    def get_cwes_for_threat(db: Session, threat_id: int) -> List[CWE]:
        return (
            db.query(CWE)
            .join(ThreatCWE)
            .filter(ThreatCWE.threat_id == threat_id)
            .all()
        )

    @staticmethod
    def link_cwe_to_threat(db: Session, threat_id: int, cwe_db_id: int) -> ThreatCWE:
        existing = (
            db.query(ThreatCWE)
            .filter(ThreatCWE.threat_id == threat_id, ThreatCWE.cwe_id == cwe_db_id)
            .first()
        )
        if existing:
            return existing
        link = ThreatCWE(threat_id=threat_id, cwe_id=cwe_db_id)
        db.add(link)
        db.commit()
        return link

    @staticmethod
    def unlink_cwe_from_threat(db: Session, threat_id: int, cwe_db_id: int) -> bool:
        link = (
            db.query(ThreatCWE)
            .filter(ThreatCWE.threat_id == threat_id, ThreatCWE.cwe_id == cwe_db_id)
            .first()
        )
        if link:
            db.delete(link)
            db.commit()
            return True
        return False

    @staticmethod
    def get_cves_for_cwe(db: Session, cwe_db_id: int) -> List[CVE]:
        return (
            db.query(CVE).join(CVECWE).filter(CVECWE.cwe_id == cwe_db_id).all()
        )


cwe_service = CWEService()
