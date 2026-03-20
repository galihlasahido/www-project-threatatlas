import logging
from typing import Optional, List
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from app.models.cve import CVE, CVECWE, CVECPE
from app.models.cwe import CWE
from app.models.technology_stack import TechnologyStack
from app.services.nvd_client import nvd_client
from app.config import settings

logger = logging.getLogger(__name__)


class CVEService:

    @staticmethod
    def sync_cve(db: Session, cve_id: str) -> Optional[CVE]:
        """Fetch a CVE from NVD and upsert into local DB"""
        # Check if recently cached
        existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if existing:
            cache_age = datetime.now(timezone.utc) - existing.updated_at
            if cache_age < timedelta(hours=settings.nvd_cache_ttl_hours):
                return existing

        # Fetch from NVD
        vuln_data = nvd_client.get_cve(cve_id)
        if not vuln_data:
            return existing

        parsed = nvd_client.parse_cve_data(vuln_data)
        return CVEService._upsert_cve(db, parsed)

    @staticmethod
    def search_and_cache(
        db: Session,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
    ) -> List[CVE]:
        """Search NVD API and cache results locally"""
        cpe_name = None
        search_keyword = keyword

        if vendor and product:
            # Build CPE pattern for virtualMatchString
            # Include version for more accurate results
            ver = version.lower() if version else "*"
            cpe_name = f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:{ver}:*:*:*:*:*:*:*"

        # If no keyword and no CPE, use product name as keyword
        if not search_keyword and not cpe_name and product:
            search_keyword = product

        result = nvd_client.search_cves(
            keyword=search_keyword, cwe_id=cwe_id, cpe_name=cpe_name
        )
        cves = []
        for vuln in result.get("vulnerabilities", []):
            parsed = nvd_client.parse_cve_data(vuln)
            cve = CVEService._upsert_cve(db, parsed)
            if cve:
                cves.append(cve)

        # If CPE search returned nothing, fallback to keyword search
        if not cves and cpe_name and not search_keyword:
            fallback_kw = f"{vendor} {product}" + (f" {version}" if version else "")
            logger.info(f"CPE search returned 0 results, falling back to keyword: {fallback_kw}")
            result = nvd_client.search_cves(keyword=fallback_kw)
            for vuln in result.get("vulnerabilities", []):
                parsed = nvd_client.parse_cve_data(vuln)
                cve = CVEService._upsert_cve(db, parsed)
                if cve:
                    cves.append(cve)

        return cves

    @staticmethod
    def get_local_cves(
        db: Session,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        severity: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[CVE]:
        """Search local CVE database"""
        query = db.query(CVE)

        if keyword:
            query = query.filter(
                CVE.description.ilike(f"%{keyword}%")
                | CVE.cve_id.ilike(f"%{keyword}%")
            )
        if severity:
            query = query.filter(CVE.cvss_v3_severity == severity.upper())
        if cwe_id:
            query = query.join(CVECWE).join(CWE).filter(CWE.cwe_id == cwe_id)
        if vendor or product:
            query = query.join(CVECPE)
            if vendor:
                query = query.filter(CVECPE.vendor == vendor.lower())
            if product:
                query = query.filter(CVECPE.product == product.lower())

        return (
            query.order_by(CVE.cvss_v3_score.desc().nullslast())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_cves_for_diagram(db: Session, diagram_id: int) -> List[dict]:
        """Get all CVEs matching technology stacks on a diagram"""
        tech_stacks = (
            db.query(TechnologyStack)
            .filter(TechnologyStack.diagram_id == diagram_id)
            .all()
        )
        results = []
        seen_cve_ids = set()

        for tech in tech_stacks:
            query = db.query(CVE).join(CVECPE)
            if tech.vendor:
                query = query.filter(CVECPE.vendor == tech.vendor.lower())
            query = query.filter(CVECPE.product == tech.technology_name.lower())

            for cve in query.all():
                if cve.id not in seen_cve_ids:
                    seen_cve_ids.add(cve.id)
                    results.append(
                        {
                            "cve": cve,
                            "technology": tech.technology_name,
                            "version": tech.version,
                            "element_id": tech.element_id,
                        }
                    )

        return results

    @staticmethod
    def get_cves_for_product(db: Session, product_id: int) -> List[dict]:
        """Get all CVEs affecting a product (across all its diagrams)"""
        from app.models.diagram import Diagram

        diagrams = (
            db.query(Diagram).filter(Diagram.product_id == product_id).all()
        )
        all_results = []
        seen_cve_ids = set()

        for diagram in diagrams:
            for item in CVEService.get_cves_for_diagram(db, diagram.id):
                if item["cve"].id not in seen_cve_ids:
                    seen_cve_ids.add(item["cve"].id)
                    item["diagram_id"] = diagram.id
                    item["diagram_name"] = diagram.name
                    all_results.append(item)

        return all_results

    @staticmethod
    def get_vulnerability_summary(
        db: Session, product_ids: Optional[List[int]] = None
    ) -> dict:
        """Get aggregated vulnerability summary for dashboard"""
        from app.models.diagram import Diagram

        query = db.query(TechnologyStack)
        if product_ids:
            query = query.join(Diagram).filter(
                Diagram.product_id.in_(product_ids)
            )
        tech_stacks = query.all()

        all_cve_ids = set()
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        top_cves = []

        for tech in tech_stacks:
            cve_query = (
                db.query(CVE)
                .join(CVECPE)
                .filter(CVECPE.product == tech.technology_name.lower())
            )
            if tech.vendor:
                cve_query = cve_query.filter(CVECPE.vendor == tech.vendor.lower())

            for cve in cve_query.all():
                if cve.id not in all_cve_ids:
                    all_cve_ids.add(cve.id)
                    sev = (cve.cvss_v3_severity or "").upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                    top_cves.append(cve)

        # Sort by CVSS score desc, take top 10
        top_cves.sort(key=lambda c: c.cvss_v3_score or 0, reverse=True)

        return {
            "total": len(all_cve_ids),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "top_cves": top_cves[:10],
        }

    @staticmethod
    def _upsert_cve(db: Session, parsed: dict) -> Optional[CVE]:
        """Insert or update a CVE record"""
        try:
            cve = db.query(CVE).filter(CVE.cve_id == parsed["cve_id"]).first()
            if not cve:
                cve = CVE(
                    cve_id=parsed["cve_id"],
                    description=parsed["description"],
                    cvss_v3_score=parsed["cvss_v3_score"],
                    cvss_v3_vector=parsed["cvss_v3_vector"],
                    cvss_v3_severity=parsed["cvss_v3_severity"],
                    published_date=parsed.get("published_date"),
                    last_modified_date=parsed.get("last_modified_date"),
                    source_url=parsed["source_url"],
                    status=parsed["status"],
                    raw_json=parsed["raw_json"],
                )
                db.add(cve)
                db.flush()
            else:
                cve.description = parsed["description"]
                cve.cvss_v3_score = parsed["cvss_v3_score"]
                cve.cvss_v3_vector = parsed["cvss_v3_vector"]
                cve.cvss_v3_severity = parsed["cvss_v3_severity"]
                cve.published_date = parsed.get("published_date")
                cve.last_modified_date = parsed.get("last_modified_date")
                cve.status = parsed["status"]
                cve.raw_json = parsed["raw_json"]
                db.flush()

            # Link CWEs
            for cwe_id_str in parsed.get("cwe_ids", []):
                cwe = db.query(CWE).filter(CWE.cwe_id == cwe_id_str).first()
                if cwe:
                    existing_link = (
                        db.query(CVECWE)
                        .filter(CVECWE.cve_id == cve.id, CVECWE.cwe_id == cwe.id)
                        .first()
                    )
                    if not existing_link:
                        db.add(CVECWE(cve_id=cve.id, cwe_id=cwe.id))

            # Link CPEs (deduplicate by cpe_uri within the same batch)
            seen_cpe_uris = set()
            for cpe_data in parsed.get("cpes", []):
                cpe_uri = cpe_data["cpe_uri"]
                if cpe_uri in seen_cpe_uris:
                    continue
                seen_cpe_uris.add(cpe_uri)
                existing_cpe = (
                    db.query(CVECPE)
                    .filter(
                        CVECPE.cve_id == cve.id,
                        CVECPE.cpe_uri == cpe_uri,
                    )
                    .first()
                )
                if not existing_cpe:
                    db.add(
                        CVECPE(
                            cve_id=cve.id,
                            cpe_uri=cpe_uri,
                            vendor=cpe_data.get("vendor"),
                            product=cpe_data.get("product"),
                            version=cpe_data.get("version"),
                        )
                    )

            db.commit()
            return cve
        except Exception as e:
            logger.error(f"Error upserting CVE {parsed.get('cve_id')}: {e}")
            db.rollback()
            return None


cve_service = CVEService()
