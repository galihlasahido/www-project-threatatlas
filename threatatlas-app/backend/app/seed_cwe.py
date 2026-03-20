"""
CWE seed data — populates CWE records and links them to existing threats.

Called from seed_knowledge_base() after frameworks/threats are seeded.
Fully idempotent: safe to run multiple times.
"""

import logging

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.cwe import CWE, ThreatCWE
from app.models.threat import Threat

logger = logging.getLogger(__name__)


# ── CWE Data ─────────────────────────────────────────────────────────────────
# ~50 common CWEs relevant to web application threat modeling.

CWE_DATA = [
    {
        "cwe_id": "CWE-20",
        "name": "Improper Input Validation",
        "description": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties required to process the data safely and correctly.",
        "category": "Input Validation",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/20.html",
    },
    {
        "cwe_id": "CWE-22",
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The product uses external input to construct a pathname that is intended to identify a file or directory below a restricted parent directory, but does not properly neutralize special elements.",
        "category": "Input Validation",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/22.html",
    },
    {
        "cwe_id": "CWE-77",
        "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        "description": "The product constructs all or part of a command using externally-influenced input, but does not neutralize or incorrectly neutralizes special elements that could modify the intended command.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/77.html",
    },
    {
        "cwe_id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "description": "The product constructs all or part of an OS command using externally-influenced input, but does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
    },
    {
        "cwe_id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
    },
    {
        "cwe_id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The product constructs all or part of an SQL command using externally-influenced input, but does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
    },
    {
        "cwe_id": "CWE-94",
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "description": "The product constructs all or part of a code segment using externally-influenced input, but does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/94.html",
    },
    {
        "cwe_id": "CWE-200",
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        "category": "Information Disclosure",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/200.html",
    },
    {
        "cwe_id": "CWE-250",
        "name": "Execution with Unnecessary Privileges",
        "description": "The product performs an operation at a privilege level that is higher than the minimum level required.",
        "category": "Privilege Management",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/250.html",
    },
    {
        "cwe_id": "CWE-269",
        "name": "Improper Privilege Management",
        "description": "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control.",
        "category": "Privilege Management",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/269.html",
    },
    {
        "cwe_id": "CWE-284",
        "name": "Improper Access Control",
        "description": "The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
        "category": "Access Control",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/284.html",
    },
    {
        "cwe_id": "CWE-287",
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.",
        "category": "Authentication",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/287.html",
    },
    {
        "cwe_id": "CWE-306",
        "name": "Missing Authentication for Critical Function",
        "description": "The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
        "category": "Authentication",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/306.html",
    },
    {
        "cwe_id": "CWE-311",
        "name": "Missing Encryption of Sensitive Data",
        "description": "The product does not encrypt sensitive or critical information before storage or transmission.",
        "category": "Cryptography",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/311.html",
    },
    {
        "cwe_id": "CWE-312",
        "name": "Cleartext Storage of Sensitive Information",
        "description": "The product stores sensitive information in cleartext within a resource that might be accessible to another control sphere.",
        "category": "Cryptography",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/312.html",
    },
    {
        "cwe_id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "description": "The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.",
        "category": "Cryptography",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/326.html",
    },
    {
        "cwe_id": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "The product uses a broken or risky cryptographic algorithm or protocol.",
        "category": "Cryptography",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/327.html",
    },
    {
        "cwe_id": "CWE-330",
        "name": "Use of Insufficiently Random Values",
        "description": "The product uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.",
        "category": "Cryptography",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/330.html",
    },
    {
        "cwe_id": "CWE-346",
        "name": "Origin Validation Error",
        "description": "The product does not properly verify that the source of data or communication is valid.",
        "category": "Input Validation",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/346.html",
    },
    {
        "cwe_id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        "category": "Session Management",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/352.html",
    },
    {
        "cwe_id": "CWE-362",
        "name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "description": "The product contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource.",
        "category": "Resource Management",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/362.html",
    },
    {
        "cwe_id": "CWE-400",
        "name": "Uncontrolled Resource Consumption",
        "description": "The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed.",
        "category": "Resource Management",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/400.html",
    },
    {
        "cwe_id": "CWE-434",
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
        "category": "Input Validation",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/434.html",
    },
    {
        "cwe_id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "description": "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        "category": "Input Validation",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/502.html",
    },
    {
        "cwe_id": "CWE-522",
        "name": "Insufficiently Protected Credentials",
        "description": "The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.",
        "category": "Authentication",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/522.html",
    },
    {
        "cwe_id": "CWE-532",
        "name": "Insertion of Sensitive Information into Log File",
        "description": "Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information.",
        "category": "Information Disclosure",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/532.html",
    },
    {
        "cwe_id": "CWE-601",
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "description": "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.",
        "category": "Input Validation",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/601.html",
    },
    {
        "cwe_id": "CWE-611",
        "name": "Improper Restriction of XML External Entity Reference",
        "description": "The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/611.html",
    },
    {
        "cwe_id": "CWE-613",
        "name": "Insufficient Session Expiration",
        "description": "The product does not sufficiently expire session identifiers, which can result in the exposure of unauthorized actions through the reuse of still-valid session identifiers.",
        "category": "Session Management",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/613.html",
    },
    {
        "cwe_id": "CWE-639",
        "name": "Authorization Bypass Through User-Controlled Key",
        "description": "The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.",
        "category": "Access Control",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/639.html",
    },
    {
        "cwe_id": "CWE-640",
        "name": "Weak Password Recovery Mechanism for Forgotten Password",
        "description": "The product contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak.",
        "category": "Authentication",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/640.html",
    },
    {
        "cwe_id": "CWE-662",
        "name": "Improper Synchronization",
        "description": "The product utilizes multiple threads or processes to allow temporary access to a shared resource that can only be exclusive to one process at a time, but it does not properly synchronize these accesses.",
        "category": "Resource Management",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/662.html",
    },
    {
        "cwe_id": "CWE-693",
        "name": "Protection Mechanism Failure",
        "description": "The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks.",
        "category": "Security Configuration",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/693.html",
    },
    {
        "cwe_id": "CWE-732",
        "name": "Incorrect Permission Assignment for Critical Resource",
        "description": "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.",
        "category": "Privilege Management",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/732.html",
    },
    {
        "cwe_id": "CWE-776",
        "name": "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
        "description": "The product uses XML documents and allows their structure to be defined with a DTD, but does not properly control the number of recursive definitions of entities.",
        "category": "Injection",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/776.html",
    },
    {
        "cwe_id": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "description": "The product contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication, or encryption.",
        "category": "Authentication",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/798.html",
    },
    {
        "cwe_id": "CWE-829",
        "name": "Inclusion of Functionality from Untrusted Control Sphere",
        "description": "The product imports, requires, or includes executable functionality from a source that is outside of the intended control sphere.",
        "category": "Supply Chain",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/829.html",
    },
    {
        "cwe_id": "CWE-862",
        "name": "Missing Authorization",
        "description": "The product does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        "category": "Access Control",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/862.html",
    },
    {
        "cwe_id": "CWE-863",
        "name": "Incorrect Authorization",
        "description": "The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.",
        "category": "Access Control",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/863.html",
    },
    {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        "category": "Input Validation",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/918.html",
    },
    {
        "cwe_id": "CWE-937",
        "name": "Using Components with Known Vulnerabilities",
        "description": "The product uses third-party components that have known security vulnerabilities.",
        "category": "Supply Chain",
        "severity": "high",
        "url": "https://cwe.mitre.org/data/definitions/937.html",
    },
    {
        "cwe_id": "CWE-942",
        "name": "Permissive Cross-domain Policy with Untrusted Domains",
        "description": "The product uses a cross-domain policy file that includes domains that should not be trusted.",
        "category": "Security Configuration",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/942.html",
    },
    {
        "cwe_id": "CWE-1021",
        "name": "Improper Restriction of Rendered UI Layers or Frames",
        "description": "The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.",
        "category": "Input Validation",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/1021.html",
    },
    {
        "cwe_id": "CWE-1104",
        "name": "Use of Unmaintained Third Party Components",
        "description": "The product relies on third-party components that are not actively maintained or supported.",
        "category": "Supply Chain",
        "severity": "medium",
        "url": "https://cwe.mitre.org/data/definitions/1104.html",
    },
]


# ── Threat-CWE Mappings ──────────────────────────────────────────────────────
# Maps CWE IDs to threat names (as they appear in the seed data).
# A single CWE can map to multiple threats across different frameworks.

THREAT_CWE_MAPPINGS = {
    "CWE-20": [
        "Parameter Tampering",
        "Input Validation and Sanitization",
    ],
    "CWE-22": [
        "Directory Traversal",
        "Path Traversal Attack",
    ],
    "CWE-77": [
        "Code Injection",
        "OS Command Injection",
    ],
    "CWE-78": [
        "OS Command Injection",
    ],
    "CWE-79": [
        "Cross-Site Scripting (XSS)",
    ],
    "CWE-89": [
        "SQL Injection",
    ],
    "CWE-94": [
        "Code Injection",
    ],
    "CWE-200": [
        "Sensitive Data Exposure in Logs",
        "Information Leakage via Error Messages",
    ],
    "CWE-250": [
        "Privilege Escalation via IDOR",
        "Privilege Escalation",
    ],
    "CWE-269": [
        "Authorization Bypass",
        "Missing Function Level Access Control",
    ],
    "CWE-284": [
        "Authorization Bypass",
        "Broken Object Level Authorization",
    ],
    "CWE-287": [
        "Authentication Bypass",
        "Credential Theft via Phishing",
    ],
    "CWE-306": [
        "Missing Multi-Factor Authentication",
        "Insufficient API Authentication",
    ],
    "CWE-311": [
        "Unencrypted Data Transmission",
        "Transmission of Sensitive Data in Cleartext",
    ],
    "CWE-312": [
        "Memory Dump Exposure",
    ],
    "CWE-326": [
        "Weak Encryption Algorithm Usage",
    ],
    "CWE-327": [
        "Hardcoded Cryptographic Keys",
    ],
    "CWE-330": [
        "Session Hijacking",
    ],
    "CWE-346": [
        "Cross-Site Request Forgery (CSRF)",
        "DNS Spoofing",
    ],
    "CWE-352": [
        "Cross-Site Request Forgery (CSRF)",
    ],
    "CWE-362": [
        "Resource Exhaustion Attack",
    ],
    "CWE-400": [
        "Resource Exhaustion Attack",
        "Application-Layer DDoS",
    ],
    "CWE-434": [
        "File Upload Exploitation",
    ],
    "CWE-502": [
        "Insecure Deserialization",
    ],
    "CWE-522": [
        "Credential Stuffing Vulnerability",
        "Default Credentials in Production",
    ],
    "CWE-532": [
        "Sensitive Data Exposure in Logs",
        "Insufficient Audit Logging",
    ],
    "CWE-601": [
        "DNS Spoofing",
    ],
    "CWE-611": [
        "XML External Entity (XXE) Injection",
        "XML Bomb (Billion Laughs)",
    ],
    "CWE-613": [
        "Session Hijacking",
        "Session Fixation",
    ],
    "CWE-639": [
        "Insecure Direct Object References",
        "Insecure Direct Object References (IDOR)",
    ],
    "CWE-640": [
        "Insecure Password Recovery",
    ],
    "CWE-662": [
        "Clock Manipulation",
    ],
    "CWE-693": [
        "Missing Security Headers",
    ],
    "CWE-732": [
        "Privilege Escalation via IDOR",
    ],
    "CWE-776": [
        "XML Bomb (Billion Laughs)",
    ],
    "CWE-798": [
        "Hardcoded Cryptographic Keys",
        "Default Credentials in Production",
    ],
    "CWE-829": [
        "Use of Components with Known Vulnerabilities",
    ],
    "CWE-862": [
        "Authorization Bypass",
        "Missing Function Level Access Control",
    ],
    "CWE-863": [
        "Privilege Escalation via IDOR",
    ],
    "CWE-918": [
        "Server-Side Request Forgery (SSRF)",
    ],
    "CWE-937": [
        "Use of Components with Known Vulnerabilities",
        "Unpatched Software",
    ],
    "CWE-942": [
        "Man-in-the-Middle Attack",
    ],
    "CWE-1021": [
        "Cross-Site Scripting (XSS)",
    ],
    "CWE-1104": [
        "Lack of Dependency Scanning",
    ],
}


# ── Seeder ────────────────────────────────────────────────────────────────────

def seed_cwes(db_session: Session = None) -> None:
    """
    Seed CWE records and link them to existing Threat records.

    Fully idempotent: existing CWE records are skipped, existing links are
    not duplicated.

    Parameters
    ----------
    db_session : Session, optional
        If provided, uses the given session. Otherwise creates a new one
        from SessionLocal.
    """
    owns_session = db_session is None
    db = db_session or SessionLocal()

    try:
        # 1. Seed CWE records
        existing_cwe_ids = {
            row[0] for row in db.query(CWE.cwe_id).all()
        }

        new_cwes = []
        for cwe_data in CWE_DATA:
            if cwe_data["cwe_id"] not in existing_cwe_ids:
                new_cwes.append(CWE(**cwe_data))

        if new_cwes:
            db.bulk_save_objects(new_cwes)
            db.commit()
            logger.info("Seeded %d new CWE records.", len(new_cwes))
        else:
            logger.debug("All CWE records already exist — nothing to seed.")

        # 2. Link CWEs to Threats
        # Build a lookup of CWE DB records by cwe_id
        cwe_lookup = {
            cwe.cwe_id: cwe
            for cwe in db.query(CWE).all()
        }

        # Build a lookup of all threats by name (across all frameworks)
        threat_lookup = {}
        for threat in db.query(Threat).all():
            threat_lookup.setdefault(threat.name, []).append(threat)

        # Get existing threat-CWE links to avoid duplicates
        existing_links = set()
        for row in db.query(ThreatCWE.threat_id, ThreatCWE.cwe_id).all():
            existing_links.add((row[0], row[1]))

        new_links = []
        for cwe_id_str, threat_names in THREAT_CWE_MAPPINGS.items():
            cwe_record = cwe_lookup.get(cwe_id_str)
            if not cwe_record:
                logger.warning("CWE %s not found in database — skipping links.", cwe_id_str)
                continue

            for threat_name in threat_names:
                threats = threat_lookup.get(threat_name, [])
                if not threats:
                    logger.debug(
                        "Threat '%s' not found for %s — skipping.",
                        threat_name, cwe_id_str,
                    )
                    continue

                for threat in threats:
                    if (threat.id, cwe_record.id) not in existing_links:
                        new_links.append(
                            ThreatCWE(threat_id=threat.id, cwe_id=cwe_record.id)
                        )
                        existing_links.add((threat.id, cwe_record.id))

        if new_links:
            db.bulk_save_objects(new_links)
            db.commit()
            logger.info("Created %d new threat-CWE links.", len(new_links))
        else:
            logger.debug("All threat-CWE links already exist — nothing to create.")

        logger.info("CWE seeding complete.")

    except Exception:
        db.rollback()
        logger.exception("CWE seeding failed — rolled back.")
        raise
    finally:
        if owns_session:
            db.close()
