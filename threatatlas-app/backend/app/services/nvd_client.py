import requests
import time
import logging
from typing import Optional, Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)


class NVDClient:
    """Client for the NIST National Vulnerability Database API v2.0"""

    def __init__(self):
        self.base_url = settings.nvd_api_base_url
        self.api_key = settings.nvd_api_key
        self.last_request_time = 0
        # Rate limiting: 5 req/30s without key, 50/30s with key
        self.min_interval = 6.0 if not self.api_key else 0.6

    def _get_headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()

    def search_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cwe_id: Optional[str] = None,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """Search CVEs from NVD API"""
        self._rate_limit()
        params: Dict[str, Any] = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            # Use virtualMatchString for CPE pattern matching (supports wildcards)
            # cpeName requires an exact registered CPE, virtualMatchString does prefix matching
            params["virtualMatchString"] = cpe_name
        if cwe_id:
            params["cweId"] = cwe_id

        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=self._get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"NVD API error: {e}")
            return {"vulnerabilities": [], "totalResults": 0}

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CVE by ID"""
        self._rate_limit()
        try:
            response = requests.get(
                self.base_url,
                params={"cveId": cve_id},
                headers=self._get_headers(),
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            return vulns[0] if vulns else None
        except Exception as e:
            logger.error(f"NVD API error fetching {cve_id}: {e}")
            return None

    def parse_cve_data(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NVD API vulnerability response into our CVE model format"""
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id", "")

        # Get description (English)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Get CVSS v3.1 metrics
        metrics = cve.get("metrics", {})
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v3_severity = None

        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
                cvss_v3_severity = cvss_data.get("baseSeverity")
                break

        # Get CWE IDs
        cwe_ids = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        # Get CPE entries
        cpes = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        cpes.append(
                            {
                                "cpe_uri": criteria,
                                "vendor": parts[3] if len(parts) > 3 else None,
                                "product": parts[4] if len(parts) > 4 else None,
                                "version": parts[5]
                                if len(parts) > 5 and parts[5] != "*"
                                else None,
                            }
                        )

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v3_severity": cvss_v3_severity,
            "published_date": cve.get("published"),
            "last_modified_date": cve.get("lastModified"),
            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "status": cve.get("vulnStatus"),
            "cwe_ids": cwe_ids,
            "cpes": cpes,
            "raw_json": vuln_data,
        }


nvd_client = NVDClient()
