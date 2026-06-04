from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .db import connect_db, close_db
from .routers import scan, vulns, auth_test, reports

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()

app = FastAPI(
    title="NetAudit API",
    description="Network discovery & security audit platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router,      prefix="/api/scan",      tags=["Scan"])
app.include_router(vulns.router,     prefix="/api/vulns",     tags=["Vulnerabilities"])
app.include_router(auth_test.router, prefix="/api/auth-test", tags=["Auth Testing"])
app.include_router(reports.router,   prefix="/api/reports",   tags=["Reports"])

@app.get("/health")
async def health():
    return {"status": "ok"}
