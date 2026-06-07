from fastapi import APIRouter, HTTPException
import asyncio, asyncssh, aioftp, telnetlib, uuid
from datetime import datetime

from ..db import get_db
from ..schemas import AuthTestConfig, AuthTestResult

router = APIRouter()

async def test_ssh(ip: str, port: int, user: str, password: str) -> bool:
    try:
        async with asyncssh.connect(
            ip, port=port, username=user, password=password,
            known_hosts=None, login_timeout=5,
        ):
            return True
    except Exception:
        return False

async def test_ftp(ip: str, port: int, user: str, password: str) -> bool:
    try:
        async with aioftp.Client.context(ip, port=port, user=user, password=password) as client:
            await client.get_current_directory()
            return True
    except Exception:
        return False

async def test_smb(ip: str, port: int, user: str, password: str) -> bool:
    try:
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        conn = Connection(uuid.uuid4(), ip, port)
        conn.connect()
        session = Session(conn, user, password)
        session.connect()
        conn.disconnect()
        return True
    except Exception:
        return False

async def test_telnet(ip: str, port: int, user: str, password: str) -> bool:
    try:
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn.read_until(b"login:", timeout=3)
        tn.write(user.encode() + b"\n")
        tn.read_until(b"Password:", timeout=3)
        tn.write(password.encode() + b"\n")
        result = tn.read_some().decode(errors="replace")
        tn.close()
        return "incorrect" not in result.lower() and len(result) > 0
    except Exception:
        return False

async def test_rdp(ip: str, port: int, user: str, password: str) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=5
        )
        rdp_conn_request = (
            b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01"
            b"\x00\x08\x00\x03\x00\x00\x00"
        )
        writer.write(rdp_conn_request)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=5)
        writer.close()
        await writer.wait_closed()
        return len(resp) > 0 and resp[0] == 0x03
    except Exception:
        return False

SERVICE_TESTERS = {
    "ssh": test_ssh,
    "sftp": test_ssh,
    "ftp": test_ftp,
    "smb": test_smb,
    "telnet": test_telnet,
    "rdp": test_rdp,
}

@router.post("/run", summary="Run authorised authentication tests")
async def run_auth_tests(config: AuthTestConfig):
    db = get_db()
    results = []
    tester = SERVICE_TESTERS.get(config.service.lower())
    if not tester:
        raise HTTPException(400, f"Service non supporté: {config.service}. Supportés: {', '.join(SERVICE_TESTERS.keys())}")

    attempts = 0
    for cred in config.credentials:
        if attempts >= config.max_attempts:
            break
        await asyncio.sleep(config.delay_seconds)
        success = await tester(config.host_ip, config.port, cred.username, cred.password)
        result = AuthTestResult(
            host_ip=config.host_ip,
            port=config.port,
            service=config.service,
            username=cred.username,
            password=cred.password,
            success=success,
            scan_id=config.scan_id,
        )
        await db.auth_results.insert_one(result.model_dump())
        results.append(result.model_dump())
        attempts += 1

    return {"tested": len(results), "results": results}

@router.get("/{scan_id}", summary="Get auth test results for a scan")
async def get_auth_results(scan_id: str, success_only: bool = False):
    db = get_db()
    query: dict = {"scan_id": scan_id}
    if success_only:
        query["success"] = True
    docs = await db.auth_results.find(query).to_list(1000)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs
