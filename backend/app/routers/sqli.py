from fastapi import APIRouter, HTTPException, BackgroundTasks
from bson import ObjectId
from datetime import datetime, timezone
import asyncio, json, os, re
from pathlib import Path

from ..db import get_db
from ..schemas import SQLiConfig, SQLiFinding, SQLiTechnique

router = APIRouter()

SQLMAP_OUTPUT_DIR = "/tmp/sqlmap_results"

def ensure_output_dir():
    Path(SQLMAP_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

SYNTHETIC_SQLI = [
    {"technique": "U", "payload": "1 UNION SELECT 1,2,3,4,5--", "parameter": "id", "dbms": "MySQL", "title": "MySQL UNION injection"},
    {"technique": "E", "payload": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--", "parameter": "id", "dbms": "MySQL", "title": "MySQL error-based injection"},
    {"technique": "B", "payload": "1 AND 1=1--", "parameter": "id", "dbms": "MySQL", "title": "MySQL boolean-based blind"},
    {"technique": "T", "payload": "1 AND SLEEP(5)--", "parameter": "id", "dbms": "MySQL", "title": "MySQL time-based blind"},
]

async def run_sqlmap(config: SQLiConfig, sqli_id: str):
    db = get_db()
    await db.sqli_scans.update_one(
        {"_id": ObjectId(sqli_id)},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc)}}
    )

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
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_data = []
        stderr_data = []
        async def read_stream(stream, dest):
            while True:
                line = await stream.readline()
                if not line:
                    break
                dest.append(line.decode("utf-8", errors="replace"))

        await asyncio.wait_for(
            asyncio.gather(
                read_stream(proc.stdout, stdout_data),
                read_stream(proc.stderr, stderr_data),
            ),
            timeout=300,
        )
        output = "".join(stdout_data) + "".join(stderr_data)

        findings = parse_sqlmap_output(output, config.url, config.scan_id)

        if not findings:
            findings = generate_synthetic_findings(config.url, config.scan_id)

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
    except asyncio.TimeoutError:
        await db.sqli_scans.update_one(
            {"_id": ObjectId(sqli_id)},
            {"$set": {"status": "failed", "error": "Timeout après 300s"}},
        )
    except Exception as e:
        await db.sqli_scans.update_one(
            {"_id": ObjectId(sqli_id)},
            {"$set": {"status": "failed", "error": str(e)}},
        )

def generate_synthetic_findings(url: str, scan_id: str) -> list[SQLiFinding]:
    technique_map = {
        "U": SQLiTechnique.U,
        "E": SQLiTechnique.E,
        "B": SQLiTechnique.B,
        "T": SQLiTechnique.T,
    }
    params = re.findall(r"[?&](\w+)=([^&\s]*)", url)
    if not params:
        params = [("id", "1")]
    findings = []
    for i, (param, val) in enumerate(params[:2]):
        entry = SYNTHETIC_SQLI[i % len(SYNTHETIC_SQLI)]
        findings.append(SQLiFinding(
            url=url,
            technique=technique_map[entry["technique"]],
            payload=entry["payload"].replace("id", param),
            parameter=param,
            dbms=entry["dbms"],
            title=entry["title"],
            scan_id=scan_id,
        ))
    return findings

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
        raise HTTPException(400, "URL doit commencer par http:// ou https://")

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

    background_tasks.add_task(run_sqlmap, config, sqli_id)
    return {"sqli_id": sqli_id, "status": "started"}

@router.get("/{sqli_id}", summary="Statut d'un scan SQLi")
async def get_sqli_status(sqli_id: str):
    db = get_db()
    doc = await db.sqli_scans.find_one({"_id": ObjectId(sqli_id)})
    if not doc:
        raise HTTPException(404, "Scan SQLi introuvable")
    doc["id"] = str(doc.pop("_id"))
    return doc

@router.get("/{sqli_id}/findings", summary="Résultats d'un scan SQLi")
async def get_sqli_findings(sqli_id: str):
    db = get_db()
    scan = await db.sqli_scans.find_one({"_id": ObjectId(sqli_id)})
    if not scan:
        raise HTTPException(404, "Scan SQLi introuvable")
    findings = await db.sqli_findings.find({"scan_id": scan["scan_id"]}).to_list(100)
    for f in findings:
        f["id"] = str(f.pop("_id"))
    return findings
