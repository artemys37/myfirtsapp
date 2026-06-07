from fastapi import APIRouter, HTTPException, BackgroundTasks
from bson import ObjectId
from datetime import datetime, timezone
import asyncio, ipaddress, re, struct, time

from ..db import get_db
from ..schemas import ScanCampaign, ScanTarget, ScanStatus, Host, PortInfo

router = APIRouter()

SCAN_CONCURRENCY = 100
PROBE_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0

PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 161: "snmp", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-proxy",
    8443: "https", 9200: "elasticsearch", 27017: "mongodb",
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
    (re.compile(r"POP3|ready", re.I), "pop3"),
    (re.compile(r"\* OK.*IMAP", re.I), "imap"),
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

OS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-2\.0.*OpenSSH[_-](\d+)", re.I), lambda m: detect_openssh_os(int(m.group(1)))),
    (re.compile(r"vsftpd", re.I), "Linux (Unix)"),
    (re.compile(r"ProFTPD", re.I), "Linux (Unix)"),
    (re.compile(r"pure-ftpd", re.I), "Linux (Unix)"),
    (re.compile(r"Microsoft-IIS", re.I), "Windows"),
    (re.compile(r"Apache", re.I), "Linux/Unix (likely)"),
    (re.compile(r"nginx", re.I), "Linux/Unix (likely)"),
    (re.compile(r"220.*Windows", re.I), "Windows"),
    (re.compile(r"220.*Microsoft", re.I), "Windows"),
]

def detect_openssh_os(major_ver: int) -> str:
    if major_ver >= 9: return "Linux (modern)"
    if major_ver >= 7: return "Linux/BSD"
    return "Legacy Unix"

OS_TTL_MAP = [
    (64, "Linux/Unix/macOS"),
    (128, "Windows"),
    (255, "Cisco/Network device"),
    (60, "BSD/Solaris"),
]


def detect_os_from_banner(banner: str | None, ttl: int = 64) -> str:
    if banner:
        for pattern, os_name in OS_PATTERNS:
            m = pattern.search(banner)
            if m:
                return os_name(m) if callable(os_name) else os_name
    for ttl_threshold, os_name in OS_TTL_MAP:
        if abs(ttl - ttl_threshold) <= 10:
            return os_name
    return "Unknown"


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


async def probe_port(ip: str, port: int, protocol: str = "tcp") -> tuple[bool, int]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=PROBE_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return True, 64
    except Exception:
        return False, 64


async def probe_port_udp(ip: str, port: int) -> tuple[bool, int]:
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(ip, port),
        )
        transport.sendto(b"\x00")
        try:
            await asyncio.wait_for(protocol.wait_for_data(), timeout=PROBE_TIMEOUT)
            transport.close()
            return True, 64
        except asyncio.TimeoutError:
            transport.close()
            return False, 64
    except Exception:
        return False, 64


async def grab_banner(ip: str, port: int) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=BANNER_TIMEOUT
        )
        for probe in [b"\r\n", b"\n", b"GET / HTTP/1.0\r\n\r\n", b"HELP\r\n"]:
            try:
                writer.write(probe)
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                if banner:
                    writer.close()
                    await writer.wait_closed()
                    return banner.decode(errors="replace").strip()
            except Exception:
                continue
        writer.close()
        await writer.wait_closed()
    except Exception:
        return None
    return None


async def scan_port(ip: str, port: int, protocol: str) -> PortInfo | None:
    if protocol == "udp":
        open_found, ttl = await probe_port_udp(ip, port)
        banner = None
    else:
        open_found, ttl = await probe_port(ip, port)
        banner = await grab_banner(ip, port) if open_found else None

    if not open_found:
        return None

    service = detect_service(port, banner)
    version = detect_version(banner)
    os_hint = detect_os_from_banner(banner, ttl)

    return PortInfo(port=port, protocol=protocol, state="open",
                    service=service, version=version, banner=banner), os_hint


async def run_scan(scan_id: str, target: ScanTarget):
    db = get_db()
    await db.campaigns.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {"status": ScanStatus.RUNNING}},
    )
    try:
        network = ipaddress.ip_network(target.network, strict=False)
        parts = target.ports.split("-")
        port_range = range(int(parts[0]), int(parts[1]) + 1)
        sem = asyncio.Semaphore(SCAN_CONCURRENCY)

        async def bounded_scan(ip: str, port: int, proto: str):
            async with sem:
                return await scan_port(ip, port, proto)

        for ip_obj in network.hosts():
            ip = str(ip_obj)
            tasks = []
            for port in port_range:
                tasks.append(bounded_scan(ip, port, "tcp"))
            if target.include_udp:
                for port in port_range:
                    tasks.append(bounded_scan(ip, port, "udp"))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            open_ports: list[PortInfo] = []
            os_guesses = []
            for r in results:
                if isinstance(r, Exception) or r is None:
                    continue
                pinfo, oshint = r
                open_ports.append(pinfo)
                if oshint:
                    os_guesses.append(oshint)

            if open_ports:
                final_os = max(set(os_guesses), key=os_guesses.count) if os_guesses else None
                host = Host(ip=ip, ports=open_ports, os=final_os, scan_id=scan_id)
                await db.hosts.insert_one(host.model_dump())

        await db.campaigns.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"status": ScanStatus.DONE, "finished_at": datetime.now(timezone.utc)}},
        )
    except Exception:
        await db.campaigns.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"status": ScanStatus.FAILED}},
        )


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
