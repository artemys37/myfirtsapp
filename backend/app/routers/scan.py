from fastapi import APIRouter, HTTPException, BackgroundTasks
from bson import ObjectId
from datetime import datetime, timezone
import asyncio, socket, ipaddress, re

from ..db import get_db
from ..schemas import ScanCampaign, ScanTarget, ScanStatus, Host, PortInfo

router = APIRouter()

# ── Helper: simple TCP port probe ─────────────────────────────────────────────

async def probe_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 8443: "https",
    9200: "elasticsearch", 27017: "mongodb",
}

BANNER_SERVICE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-[\d.]+", re.I), "ssh"),
    (re.compile(r"220.*ftp", re.I), "ftp"),
    (re.compile(r"220.*vsftpd", re.I), "ftp"),
    (re.compile(r"530.*ftp", re.I), "ftp"),
    (re.compile(r"HTTP/[\d.]+", re.I), "http"),
    (re.compile(r"^HTTP", re.I), "http"),
    (re.compile(r"SMTP", re.I), "smtp"),
    (re.compile(r"220.*ESMTP", re.I), "smtp"),
    (re.compile(r"220.*SMTP", re.I), "smtp"),
    (re.compile(r"POP3|ready", re.I), "pop3"),
    (re.compile(r"\* OK.*IMAP", re.I), "imap"),
    (re.compile(r"IMAP.*ready", re.I), "imap"),
    (re.compile(r"MongoDB", re.I), "mongodb"),
    (re.compile(r"Redis", re.I), "redis"),
    (re.compile(r"MySQL", re.I), "mysql"),
    (re.compile(r"PostgreSQL", re.I), "postgresql"),
    (re.compile(r"220.*ProFTPD", re.I), "ftp"),
    (re.compile(r"220.*pure-ftpd", re.I), "ftp"),
    (re.compile(r"Elasticsearch", re.I), "elasticsearch"),
]

VERSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-([\d.]+)", re.I), r"\1"),
    (re.compile(r"vsftpd ([\d.]+)", re.I), r"\1"),
    (re.compile(r"ProFTPD ([\d.]+)", re.I), r"\1"),
    (re.compile(r"pure-ftpd.*v?([\d.]+)", re.I), r"\1"),
    (re.compile(r"Apache/([\d.]+)", re.I), r"\1"),
    (re.compile(r"nginx/([\d.]+)", re.I), r"\1"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), r"\1"),
    (re.compile(r"OpenSSH[_-]([\d.]+)", re.I), r"\1"),
    (re.compile(r"MySQL.*v?([\d.]+)", re.I), r"\1"),
    (re.compile(r"PostgreSQL ([\d.]+)", re.I), r"\1"),
    (re.compile(r"Redis.*v?([\d.]+)", re.I), r"\1"),
]


def detect_service(port: int, banner: str | None) -> str:
    if banner:
        for pattern, svc in BANNER_SERVICE_PATTERNS:
            if pattern.search(banner):
                return svc
    return PORT_SERVICES.get(port, "")


def detect_version(banner: str | None) -> str:
    if not banner:
        return ""
    for pattern, repl in VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            return m.expand(repl)
    return ""


async def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(b"\r\n")
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return banner.decode(errors="replace").strip()
    except Exception:
        return None

# ── Background scan task ───────────────────────────────────────────────────────

async def run_scan(scan_id: str, target: ScanTarget):
    db = get_db()
    await db.campaigns.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {"status": ScanStatus.RUNNING}},
    )
    try:
        network = ipaddress.ip_network(target.network, strict=False)
        port_range = range(
            int(target.ports.split("-")[0]),
            int(target.ports.split("-")[1]) + 1,
        )
        for ip_obj in network.hosts():
            ip = str(ip_obj)
            open_ports: list[PortInfo] = []
            for port in port_range:
                if await probe_port(ip, port):
                    banner = await grab_banner(ip, port)
                    service = detect_service(port, banner)
                    version = detect_version(banner)
                    open_ports.append(
                        PortInfo(port=port, state="open", service=service, version=version, banner=banner)
                    )
            if open_ports:
                host = Host(ip=ip, ports=open_ports, scan_id=scan_id)
                await db.hosts.insert_one(host.model_dump())
        await db.campaigns.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"status": ScanStatus.DONE, "finished_at": datetime.now(timezone.utc)}},
        )
    except Exception as e:
        await db.campaigns.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"status": ScanStatus.FAILED}},
        )

# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/start", summary="Launch a new scan campaign")
async def start_scan(campaign: ScanCampaign, background_tasks: BackgroundTasks):
    db = get_db()
    result = await db.campaigns.insert_one(campaign.model_dump())
    scan_id = str(result.inserted_id)
    background_tasks.add_task(run_scan, scan_id, campaign.target)
    return {"scan_id": scan_id, "status": "started"}

@router.get("/{scan_id}", summary="Get scan campaign status")
async def get_scan(scan_id: str):
    db = get_db()
    doc = await db.campaigns.find_one({"_id": ObjectId(scan_id)})
    if not doc:
        raise HTTPException(404, "Scan not found")
    doc["id"] = str(doc.pop("_id"))
    return doc

@router.get("/{scan_id}/hosts", summary="List discovered hosts")
async def get_hosts(scan_id: str):
    db = get_db()
    hosts = await db.hosts.find({"scan_id": scan_id}).to_list(1000)
    for h in hosts:
        h["id"] = str(h.pop("_id"))
    return hosts

@router.get("/", summary="List all campaigns")
async def list_campaigns():
    db = get_db()
    campaigns = await db.campaigns.find().sort("created_at", -1).to_list(100)
    for c in campaigns:
        c["id"] = str(c.pop("_id"))
    return campaigns
