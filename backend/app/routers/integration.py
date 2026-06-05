from fastapi import APIRouter
from datetime import datetime, timezone
import platform, sys

from ..db import get_db

router = APIRouter()

BACKEND_VERSION = "1.0.0"

@router.get("/status", summary="Check full platform integration status")
async def integration_status():
    db = get_db()
    mongo_ok = False
    mongo_error = None
    db_stats = {}
    try:
        await db.command("ping")
        mongo_ok = True
        collections = ["campaigns", "hosts", "vulns", "auth_results", "reports"]
        for col_name in collections:
            count = await db[col_name].count_documents({})
            db_stats[col_name] = count
    except Exception as e:
        mongo_error = str(e)

    return {
        "status": "ok" if mongo_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "backend": {
                "status": "ok",
                "version": BACKEND_VERSION,
                "python": sys.version,
                "host": platform.node(),
            },
            "database": {
                "status": "ok" if mongo_ok else "error",
                "type": "MongoDB",
                "error": mongo_error,
                "stats": db_stats,
            },
        },
    }
