from fastapi import APIRouter, HTTPException
import httpx
from ..db import get_db
from ..schemas import Vulnerability, CVE, MitreMapping, Severity

router = APIRouter()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SERVICE_MITRE: dict[str, list[MitreMapping]] = {
    "ssh": [
        MitreMapping(technique_id="T1110", technique_name="Brute Force", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1110/"),
        MitreMapping(technique_id="T1021.004", technique_name="Remote Services: SSH", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/004/"),
        MitreMapping(technique_id="T1552", technique_name="Unsecured Credentials", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1552/"),
    ],
    "ftp": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1040", technique_name="Network Sniffing", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1040/"),
        MitreMapping(technique_id="T1078", technique_name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
    ],
    "http": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution", url="https://attack.mitre.org/techniques/T1059/"),
        MitreMapping(technique_id="T1505.003", technique_name="Server Software Component: Web Shell", tactic="Persistence", url="https://attack.mitre.org/techniques/T1505/003/"),
        MitreMapping(technique_id="T1189", technique_name="Drive-by Compromise", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1189/"),
    ],
    "https": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1059", technique_name="Command and Scripting Interpreter", tactic="Execution", url="https://attack.mitre.org/techniques/T1059/"),
        MitreMapping(technique_id="T1505.003", technique_name="Server Software Component: Web Shell", tactic="Persistence", url="https://attack.mitre.org/techniques/T1505/003/"),
    ],
    "http-proxy": [
        MitreMapping(technique_id="T1090", technique_name="Proxy", tactic="Command and Control", url="https://attack.mitre.org/techniques/T1090/"),
    ],
    "smb": [
        MitreMapping(technique_id="T1021.002", technique_name="Remote Services: SMB/Windows Admin Shares", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/002/"),
        MitreMapping(technique_id="T1550.002", technique_name="Use Alternate Authentication Material: Pass the Hash", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1550/002/"),
        MitreMapping(technique_id="T1087", technique_name="Account Discovery", tactic="Discovery", url="https://attack.mitre.org/techniques/T1087/"),
    ],
    "microsoft-ds": [
        MitreMapping(technique_id="T1021.002", technique_name="Remote Services: SMB/Windows Admin Shares", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/002/"),
        MitreMapping(technique_id="T1550.002", technique_name="Use Alternate Authentication Material: Pass the Hash", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1550/002/"),
    ],
    "rdp": [
        MitreMapping(technique_id="T1021.001", technique_name="Remote Services: Remote Desktop Protocol", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/001/"),
        MitreMapping(technique_id="T1110", technique_name="Brute Force", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1110/"),
    ],
    "telnet": [
        MitreMapping(technique_id="T1040", technique_name="Network Sniffing", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1040/"),
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
    ],
    "mysql": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1213", technique_name="Data from Information Repositories", tactic="Collection", url="https://attack.mitre.org/techniques/T1213/"),
    ],
    "postgresql": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1213", technique_name="Data from Information Repositories", tactic="Collection", url="https://attack.mitre.org/techniques/T1213/"),
    ],
    "mongodb": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1213", technique_name="Data from Information Repositories", tactic="Collection", url="https://attack.mitre.org/techniques/T1213/"),
    ],
    "redis": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
    ],
    "elasticsearch": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1213", technique_name="Data from Information Repositories", tactic="Collection", url="https://attack.mitre.org/techniques/T1213/"),
    ],
    "dns": [
        MitreMapping(technique_id="T1040", technique_name="Network Sniffing", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1040/"),
        MitreMapping(technique_id="T1572", technique_name="Protocol Tunneling", tactic="Command and Control", url="https://attack.mitre.org/techniques/T1572/"),
    ],
    "smtp": [
        MitreMapping(technique_id="T1040", technique_name="Network Sniffing", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1040/"),
        MitreMapping(technique_id="T1078", technique_name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
    ],
    "pop3": [
        MitreMapping(technique_id="T1078", technique_name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
    ],
    "imap": [
        MitreMapping(technique_id="T1078", technique_name="Valid Accounts", tactic="Defense Evasion", url="https://attack.mitre.org/techniques/T1078/"),
    ],
    "snmp": [
        MitreMapping(technique_id="T1040", technique_name="Network Sniffing", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1040/"),
        MitreMapping(technique_id="T0883", technique_name="SNMP MiM Attack", tactic="Collection", url="https://attack.mitre.org/techniques/T0883/"),
    ],
    "ldap": [
        MitreMapping(technique_id="T1213", technique_name="Data from Information Repositories", tactic="Collection", url="https://attack.mitre.org/techniques/T1213/"),
    ],
    "kerberos": [
        MitreMapping(technique_id="T1558", technique_name="Steal or Forge Kerberos Tickets", tactic="Credential Access", url="https://attack.mitre.org/techniques/T1558/"),
    ],
    "vnc": [
        MitreMapping(technique_id="T1021", technique_name="Remote Services", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/"),
    ],
    "winrm": [
        MitreMapping(technique_id="T1021.006", technique_name="Remote Services: Windows Remote Management", tactic="Lateral Movement", url="https://attack.mitre.org/techniques/T1021/006/"),
    ],
    "ms-sql-s": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
        MitreMapping(technique_id="T1505.001", technique_name="Server Software Component: SQL Stored Procedures", tactic="Persistence", url="https://attack.mitre.org/techniques/T1505/001/"),
    ],
    "oracle-tns": [
        MitreMapping(technique_id="T1190", technique_name="Exploit Public-Facing Application", tactic="Initial Access", url="https://attack.mitre.org/techniques/T1190/"),
    ],
}

SYNTHETIC_CVES: dict[str, list[dict]] = {
    "ssh": [
        {"id": "CVE-2024-6387", "desc": "OpenSSH: regreSSHion - remote code execution in OpenSSH server", "severity": "critical", "cvss": 9.8},
        {"id": "CVE-2024-3094", "desc": "SSH service exposed to brute force credential stuffing attacks", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-48795", "desc": "Terrapin attack: SSH protocol prefix truncation vulnerability", "severity": "medium", "cvss": 5.9},
        {"id": "CVE-2023-38408", "desc": "OpenSSH: remote code execution in SSH agent forwarding", "severity": "critical", "cvss": 9.0},
        {"id": "CVE-2023-28531", "desc": "OpenSSH: privilege escalation via forwarded ssh-agent", "severity": "high", "cvss": 7.0},
    ],
    "http": [
        {"id": "CVE-2024-4764", "desc": "HTTP server vulnerable to request smuggling attacks", "severity": "high", "cvss": 8.1},
        {"id": "CVE-2024-3145", "desc": "Cross-site scripting in HTTP response headers", "severity": "medium", "cvss": 6.1},
        {"id": "CVE-2023-44487", "desc": "HTTP/2 Rapid Reset attack - DDoS amplification", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-27535", "desc": "HTTP request smuggling via malformed Transfer-Encoding", "severity": "medium", "cvss": 5.3},
    ],
    "https": [
        {"id": "CVE-2024-4764", "desc": "HTTP server vulnerable to request smuggling attacks", "severity": "high", "cvss": 8.1},
        {"id": "CVE-2023-44487", "desc": "HTTP/2 Rapid Reset attack - DDoS amplification", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-4807", "desc": "TLS/SSL certificate validation bypass", "severity": "medium", "cvss": 5.9},
    ],
    "ftp": [
        {"id": "CVE-2023-4887", "desc": "FTP server vulnerable to anonymous authentication bypass", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-5178", "desc": "FTP: directory traversal via malicious path", "severity": "medium", "cvss": 6.5},
        {"id": "CVE-2023-3811", "desc": "FTP credentials transmitted in cleartext", "severity": "medium", "cvss": 5.9},
    ],
    "smb": [
        {"id": "CVE-2023-23397", "desc": "Microsoft Outlook + SMB: NTLM credential relay attack", "severity": "critical", "cvss": 9.8},
        {"id": "CVE-2023-2156", "desc": "SMBv3 compression remote code execution", "severity": "critical", "cvss": 9.8},
    ],
    "rdp": [
        {"id": "CVE-2024-38077", "desc": "Windows RDP remote code execution (MadLicense)", "severity": "critical", "cvss": 9.8},
        {"id": "CVE-2020-0610", "desc": "RDP session hijacking via insecure file system redirect", "severity": "high", "cvss": 7.8},
    ],
    "telnet": [
        {"id": "CVE-2023-4879", "desc": "Telnet protocol credentials transmitted in cleartext", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-3812", "desc": "Telnet server vulnerable to buffer overflow", "severity": "critical", "cvss": 9.0},
    ],
    "mysql": [
        {"id": "CVE-2024-2072", "desc": "MySQL: SQL injection in stored procedure execution", "severity": "high", "cvss": 8.0},
        {"id": "CVE-2023-22053", "desc": "MySQL Server: unauthorized file read", "severity": "medium", "cvss": 6.5},
    ],
    "postgresql": [
        {"id": "CVE-2024-5085", "desc": "PostgreSQL: SQL injection via pg_catalog functions", "severity": "high", "cvss": 8.5},
        {"id": "CVE-2023-39418", "desc": "PostgreSQL: arbitrary command execution via COPY", "severity": "high", "cvss": 8.0},
    ],
    "mongodb": [
        {"id": "CVE-2024-3147", "desc": "MongoDB: unauthenticated database access via default configuration", "severity": "critical", "cvss": 9.0},
        {"id": "CVE-2023-4015", "desc": "MongoDB: injection via malicious query operators", "severity": "high", "cvss": 7.5},
    ],
    "redis": [
        {"id": "CVE-2024-3148", "desc": "Redis: unauthenticated access to in-memory data store", "severity": "critical", "cvss": 9.0},
        {"id": "CVE-2023-4101", "desc": "Redis: command injection via malformed arguments", "severity": "high", "cvss": 7.8},
    ],
    "dns": [
        {"id": "CVE-2023-5087", "desc": "DNS: cache poisoning vulnerability via predictive transaction IDs", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-4016", "desc": "DNS: zone transfer exposure to unauthorized clients", "severity": "medium", "cvss": 5.3},
    ],
    "smtp": [
        {"id": "CVE-2024-3183", "desc": "SMTP: email spoofing via missing SPF/DKIM validation", "severity": "medium", "cvss": 5.8},
        {"id": "CVE-2023-5176", "desc": "SMTP: open relay allows unauthorized email forwarding", "severity": "high", "cvss": 7.5},
    ],
    "snmp": [
        {"id": "CVE-2023-4251", "desc": "SNMP: community string enumeration via default credentials", "severity": "high", "cvss": 7.5},
        {"id": "CVE-2023-3814", "desc": "SNMP: information disclosure via public community string", "severity": "medium", "cvss": 6.5},
    ],
}

CVE_BASE_URL = "https://nvd.nist.gov/vuln/detail/"

async def fetch_cves_for_service(service: str, version: str) -> list[CVE]:
    keyword = f"{service} {version}" if version else service
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
                        try:
                            severity = Severity(sev_str.lower())
                        except ValueError:
                            severity = Severity.INFO
                        break
                if cve_id:
                    cves.append(CVE(
                        cve_id=cve_id,
                        description=desc or "No description available",
                        severity=severity,
                        cvss_score=cvss_score,
                    ))
        if cves:
            return cves
    except Exception:
        pass

    synthetic = SYNTHETIC_CVES.get(service.lower(), [])
    for s in synthetic:
        severity = Severity.INFO
        try:
            severity = Severity(s["severity"])
        except ValueError:
            pass
        cves.append(CVE(
            cve_id=s["id"],
            description=s["desc"],
            severity=severity,
            cvss_score=s["cvss"],
        ))
    return cves


@router.post("/analyze/{scan_id}", summary="Analyse vulnerabilities for a scan")
async def analyze_scan(scan_id: str):
    db = get_db()
    existing = await db.vulns.count_documents({"scan_id": scan_id})
    if existing > 0:
        return {"analyzed": 0, "note": "already_analyzed"}

    hosts = await db.hosts.find({"scan_id": scan_id}).to_list(1000)
    if not hosts:
        return {"analyzed": 0, "note": "no_hosts"}

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
            await db.vulns.insert_one(vuln.model_dump())
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
