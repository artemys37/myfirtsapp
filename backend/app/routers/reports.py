from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from bson import ObjectId
import json, csv, io
from datetime import datetime, timezone

from ..db import get_db
from ..schemas import ReportRequest

router = APIRouter()

async def build_report_data(scan_id: str) -> dict:
    db = get_db()
    campaign = await db.campaigns.find_one({"_id": ObjectId(scan_id)})
    hosts = await db.hosts.find({"scan_id": scan_id}).to_list(1000)
    vulns = await db.vulns.find({"scan_id": scan_id}).to_list(1000)
    auth = await db.auth_results.find({"scan_id": scan_id}).to_list(1000)

    # Stringify ObjectIds
    for col in [hosts, vulns, auth]:
        for d in col:
            d.pop("_id", None)

    return {
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "hosts": len(hosts),
            "open_ports": sum(len(h.get("ports", [])) for h in hosts),
            "vulnerabilities": len(vulns),
            "cves": sum(len(v.get("cves", [])) for v in vulns),
            "auth_successes": sum(1 for a in auth if a.get("success")),
        },
        "hosts": hosts,
        "vulnerabilities": vulns,
        "auth_results": auth,
    }

@router.post("/generate", summary="Generate a report for a scan")
async def generate_report(req: ReportRequest):
    data = await build_report_data(req.scan_id)

    if req.format == "json":
        db = get_db()
        await db.reports.insert_one({"scan_id": req.scan_id, "data": data, "format": "json", "created_at": datetime.now(timezone.utc)})
        return data

    elif req.format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["scan_id", "host_ip", "port", "service", "cve_id", "severity", "cvss"])
        for v in data["vulnerabilities"]:
            for cve in v.get("cves", []):
                writer.writerow([
                    req.scan_id, v["host_ip"], v.get("port", ""),
                    v.get("service", ""), cve["cve_id"],
                    cve.get("severity", ""), cve.get("cvss_score", ""),
                ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{req.scan_id}.csv"},
        )

    elif req.format == "pdf":
        # PDF generation requires WeasyPrint or reportlab — return JSON for now
        # TODO: integrate WeasyPrint HTML→PDF
        raise HTTPException(501, "PDF export coming soon — use json or csv for now")

    raise HTTPException(400, f"Unknown format: {req.format}")

@router.get("/{scan_id}", summary="Get stored reports for a scan")
async def list_reports(scan_id: str):
    db = get_db()
    docs = await db.reports.find({"scan_id": scan_id}).to_list(50)
    for d in docs:
        d.pop("_id", None)
    return docs
