from fastapi import APIRouter, HTTPException, BackgroundTasks
from bson import ObjectId
from datetime import datetime, timezone
import subprocess, json, os, re
from pathlib import Path

from ..db import get_db
from ..schemas import SQLiConfig, SQLiFinding, SQLiTechnique

router = APIRouter()

SQLMAP_OUTPUT_DIR = "/tmp/sqlmap_results"

def ensure_output_dir():
    Path(SQLMAP_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

async def run_sqlmap(config: SQLiConfig):
    db = get_db()
    scan_doc = {
        "url": config.url,
        "status": "running",
        "level": config.level,
        "risk": config.risk,
        "scan_id": config.scan_id,
        "created_at": datetime.now(timezone.utc),
        "findings": [],
    }
    result = await db.sqli_scans.insert_one(scan_doc)
    sqli_id = str(result.inserted_id)

    ensure_output_dir()
    output_dir = os.path.join(SQLMAP_OUTPUT_DIR, sqli_id)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        "sqlmap", "-u", config.url,
        "--batch", "--random-agent",
        f"--level={config.level}",
        f"--risk={config.risk}",
        "--output-dir=" + output_dir,
        "--flush-session",
    ]

    if config.data:
        cmd.extend(["--data", config.data])
    if config.cookie:
        cmd.extend(["--cookie", config.cookie])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = proc.stdout + proc.stderr

        findings = parse_sqlmap_output(output, config.url, config.scan_id)

        for f in findings:
            await db.sqli_findings.insert_one(f.model_dump())

        await db.sqli_scans.update_one(
            {"_id": ObjectId(sqli_id)},
            {
                "$set": {
                    "status": "done",
                    "finished_at": datetime.now(timezone.utc),
                    "findings": [f.model_dump() for f in findings],
                    "raw_output": output[-5000:],
                }
            },
        )
    except subprocess.TimeoutExpired:
        await db.sqli_scans.update_one(
            {"_id": ObjectId(sqli_id)},
            {"$set": {"status": "failed", "error": "Timeout after 300s"}},
        )
    except Exception as e:
        await db.sqli_scans.update_one(
            {"_id": ObjectId(sqli_id)},
            {"$set": {"status": "failed", "error": str(e)}},
        )

def parse_sqlmap_output(output: str, url: str, scan_id: str) -> list[SQLiFinding]:
    findings = []
    technique_map = {
        "boolean": SQLiTechnique.B,
        "error": SQLiTechnique.E,
        "union": SQLiTechnique.U,
        "stacked": SQLiTechnique.S,
        "time": SQLiTechnique.T,
        "inline": SQLiTechnique.Q,
    }

    patterns = [
        r"Parameter:\s*(\S+)\s*\((\w+)\)",
        r"Title:\s*(.+?)(?:\n|$)",
        r"Payload:\s*(.+?)(?:\n|$)",
        r"DBMS:\s*(.+?)(?:\n|$)",
    ]

    blocks = re.split(r"---\n", output)
    for block in blocks:
        if "Parameter:" not in block:
            continue
        param = None
        technique = None
        title = None
        payload = None
        dbms = None

        for line in block.split("\n"):
            pm = re.match(r"Parameter:\s*(\S+)\s*\((\w+)\)", line)
            if pm:
                param = pm.group(1)
                tech_name = pm.group(2).lower()
                technique = technique_map.get(tech_name)
            tm = re.match(r"Title:\s*(.+)", line)
            if tm:
                title = tm.group(1).strip()
            plm = re.match(r"Payload:\s*(.+)", line)
            if plm:
                payload = plm.group(1).strip()
            dm = re.match(r"DBMS:\s*(.+)", line)
            if dm:
                dbms = dm.group(1).strip()

        if technique:
            findings.append(SQLiFinding(
                url=url,
                technique=technique,
                payload=payload,
                parameter=param,
                dbms=dbms,
                title=title,
                scan_id=scan_id,
            ))

    return findings

@router.post("/run", summary="Lancer un test SQLi avec sqlmap")
async def start_sqli(config: SQLiConfig, background_tasks: BackgroundTasks):
    if not config.url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")

    db = get_db()
    doc = {
        "url": config.url,
        "status": "pending",
        "level": config.level,
        "risk": config.risk,
        "scan_id": config.scan_id,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.sqli_scans.insert_one(doc)
    sqli_id = str(result.inserted_id)
    doc["id"] = sqli_id

    background_tasks.add_task(run_sqlmap, config)
    return {"sqli_id": sqli_id, "status": "started"}

@router.get("/{sqli_id}", summary="Statut d'un scan SQLi")
async def get_sqli_status(sqli_id: str):
    db = get_db()
    doc = await db.sqli_scans.find_one({"_id": ObjectId(sqli_id)})
    if not doc:
        raise HTTPException(404, "SQLi scan not found")
    doc["id"] = str(doc.pop("_id"))
    return doc

@router.get("/{sqli_id}/findings", summary="Résultats d'un scan SQLi")
async def get_sqli_findings(sqli_id: str):
    db = get_db()
    scan = await db.sqli_scans.find_one({"_id": ObjectId(sqli_id)})
    if not scan:
        raise HTTPException(404, "SQLi scan not found")
    findings = await db.sqli_findings.find({"scan_id": scan["scan_id"]}).to_list(100)
    for f in findings:
        f["id"] = str(f.pop("_id"))
    return findings
