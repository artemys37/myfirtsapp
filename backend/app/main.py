from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .db import connect_db, close_db
from .routers import scan, vulns, auth_test, reports, integration, sqli, auth, terminal

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

app.include_router(auth.router,        prefix="/api/auth",      tags=["Authentication"])
app.include_router(scan.router,        prefix="/api/scan",      tags=["Scan"])
app.include_router(vulns.router,       prefix="/api/vulns",     tags=["Vulnerabilities"])
app.include_router(auth_test.router,   prefix="/api/auth-test", tags=["Auth Testing"])
app.include_router(reports.router,     prefix="/api/reports",   tags=["Reports"])
app.include_router(integration.router, prefix="/api/integration", tags=["Integration"])
app.include_router(sqli.router,        prefix="/api/sqli",       tags=["SQL Injection"])
app.include_router(terminal.router,    prefix="/api/terminal",  tags=["Terminal"])

@app.get("/health")
async def health():
    return {"status": "ok"}
