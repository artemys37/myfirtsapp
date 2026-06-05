from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum

# ── Enums ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

# ── Host & Port ────────────────────────────────────────────────────────────────

class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

class Host(BaseModel):
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    ports: List[PortInfo] = []
    scan_id: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ── Vulnerability ──────────────────────────────────────────────────────────────

class CVE(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Severity = Severity.INFO
    cvss_score: Optional[float] = None
    published: Optional[datetime] = None

class MitreMapping(BaseModel):
    technique_id: str          # e.g. T1190
    technique_name: str
    tactic: str                # e.g. Initial Access
    url: Optional[str] = None

class Vulnerability(BaseModel):
    host_ip: str
    port: Optional[int] = None
    service: Optional[str] = None
    cves: List[CVE] = []
    mitre: List[MitreMapping] = []
    scan_id: str
    found_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ── Scan Campaign ──────────────────────────────────────────────────────────────

class ScanTarget(BaseModel):
    network: str               # e.g. "192.168.1.0/24"
    ports: str = "1-1024"
    include_udp: bool = False

class ScanCampaign(BaseModel):
    name: str
    target: ScanTarget
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None

# ── Auth Test ──────────────────────────────────────────────────────────────────

class AuthCredential(BaseModel):
    username: str
    password: str

class AuthTestConfig(BaseModel):
    host_ip: str
    port: int
    service: str               # ssh | ftp | smb | rdp | telnet
    credentials: List[AuthCredential]
    max_attempts: int = 5
    delay_seconds: float = 1.0
    scan_id: str

class AuthTestResult(BaseModel):
    host_ip: str
    port: int
    service: str
    username: str
    password: str
    success: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str

# ── Report ─────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    scan_id: str
    format: str = "json"       # json | csv | pdf
    include_auth: bool = True
    include_vulns: bool = True
    include_mitre: bool = True
