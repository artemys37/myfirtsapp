from fastapi import APIRouter, HTTPException
import httpx
from ..db import get_db
from ..models.schemas import Vulnerability, CVE, MitreMapping, Severity

router = APIRouter()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_API = "https://attack.mitre.org/api/techniques/"

# ── CVE lookup via NVD ─────────────────────────────────────────────────────────

async def fetch_cves_for_service(service: str, version: str) -> list[CVE]:
    keyword = f"{service} {version}"
    cves = []
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": 10},
            )
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                desc = next(
                    (
                        d["value"]
                        for d in cve_data.get("descriptions", [])
                        if d["lang"] == "en"
                    ),
                    None,
                )
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                severity = Severity.INFO
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]
                        cvss_score = m.get("cvssData", {}).get("baseScore")
                        sev_str = m.get("cvssData", {}).get("baseSeverity", "INFO")
                        severity = Severity(sev_str.lower()) if sev_str.lower() in Severity._value2member_map_ else Severity.INFO
                        break
                cves.append(
                    CVE(
                        cve_id=cve_id,
                        description=desc,
                        severity=severity,
                        cvss_score=cvss_score,
                    )
                )
    except Exception:
        pass
    return cves

# ── Basic MITRE mapping (static heuristic) ─────────────────────────────────────

SERVICE_MITRE: dict[str, list[MitreMapping]] = {
    "ssh": [
        MitreMapping(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            url="https://attack.mitre.org/techniques/T1110/",
        )
    ],
    "ftp": [
        MitreMapping(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            url="https://attack.mitre.org/techniques/T1190/",
        )
    ],
    "smb": [
        MitreMapping(
            technique_id="T1021.002",
            technique_name="Remote Services: SMB/Windows Admin Shares",
            tactic="Lateral Movement",
            url="https://attack.mitre.org/techniques/T1021/002/",
        )
    ],
    "rdp": [
        MitreMapping(
            technique_id="T1021.001",
            technique_name="Remote Services: Remote Desktop Protocol",
            tactic="Lateral Movement",
            url="https://attack.mitre.org/techniques/T1021/001/",
        )
    ],
    "telnet": [
        MitreMapping(
            technique_id="T1040",
            technique_name="Network Sniffing",
            tactic="Credential Access",
            url="https://attack.mitre.org/techniques/T1040/",
        )
    ],
}

# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/analyze/{scan_id}", summary="Analyse vulnerabilities for a scan")
async def analyze_scan(scan_id: str):
    db = get_db()
    hosts = await db.hosts.find({"scan_id": scan_id}).to_list(1000)
    if not hosts:
        raise HTTPException(404, "No hosts found for this scan")

    inserted = 0
    for host in hosts:
        for port_info in host.get("ports", []):
            service = (port_info.get("service") or "").lower()
            version = port_info.get("version") or ""
            cves = await fetch_cves_for_service(service, version) if service else []
            mitre = SERVICE_MITRE.get(service, [])
            vuln = Vulnerability(
                host_ip=host["ip"],
                port=port_info.get("port"),
                service=service,
                cves=cves,
                mitre=mitre,
                scan_id=scan_id,
            )
            await db.vulns.insert_one(vuln.dict())
            inserted += 1

    return {"analyzed": inserted}

@router.get("/{scan_id}", summary="Get vulnerabilities for a scan")
async def get_vulns(scan_id: str, severity: str | None = None):
    db = get_db()
    query: dict = {"scan_id": scan_id}
    vulns = await db.vulns.find(query).to_list(1000)
    if severity:
        vulns = [
            v for v in vulns
            if any(c.get("severity") == severity for c in v.get("cves", []))
        ]
    for v in vulns:
        v["id"] = str(v.pop("_id"))
    return vulns

@router.get("/{scan_id}/mitre", summary="Get MITRE ATT&CK mappings for a scan")
async def get_mitre(scan_id: str):
    db = get_db()
    vulns = await db.vulns.find({"scan_id": scan_id}).to_list(1000)
    techniques: dict[str, dict] = {}
    for v in vulns:
        for m in v.get("mitre", []):
            techniques[m["technique_id"]] = m
    return list(techniques.values())
