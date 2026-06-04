from fastapi import APIRouter, HTTPException
import asyncio, asyncssh, aioftp
from datetime import datetime

from ..db import get_db
from ..models.schemas import AuthTestConfig, AuthTestResult

router = APIRouter()

# ── Per-service connectors ─────────────────────────────────────────────────────

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

async def test_generic_banner(ip: str, port: int, user: str, password: str) -> bool:
    """Fallback: try sending USER/PASS over raw TCP (Telnet-style)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=5
        )
        writer.write(f"{user}\r\n{password}\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=3)
        writer.close()
        await writer.wait_closed()
        resp_str = resp.decode(errors="replace").lower()
        return "welcome" in resp_str or "success" in resp_str or "logged" in resp_str
    except Exception:
        return False

SERVICE_TESTERS = {
    "ssh": test_ssh,
    "ftp": test_ftp,
}

# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/run", summary="Run authorised authentication tests")
async def run_auth_tests(config: AuthTestConfig):
    db = get_db()
    results = []
    tester = SERVICE_TESTERS.get(config.service.lower(), test_generic_banner)
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
        await db.auth_results.insert_one(result.dict())
        results.append(result.dict())
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
