from fastapi import FastAPI, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from contextlib import asynccontextmanager
import json, os, smtplib, threading, logging

logger = logging.getLogger("uvicorn")

from .db import connect_db, close_db
from .routers import scan, vulns, auth_test, reports, integration, sqli, auth, terminal, wifi, tools, lanscan

TUNNEL_URL_FILE = "/tunnel/url.json"
SENT_URLS_FILE = "/tmp/.sent_urls.json"

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "37artemys@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_TO      = os.getenv("EMAIL_TO", "37artemys@gmail.com")

def send_tunnel_email(url: str) -> bool:
    if not SMTP_PASSWORD:
        logger.warning("SMTP_PASSWORD non défini — email non envoyé")
        return False
    subject = "NetAudit Tunnel — Nouvelle URL"
    body = f"""Bonjour,

Le tunnel Cloudflare est prêt. Voici l'URL pour accéder à la plateforme NetAudit depuis l'extérieur :

🌐 {url}

Cette URL changera au prochain redémarrage du conteneur tunnel.

—
NetAudit Platform
"""
    msg = f"Subject: {subject}\nContent-Type: text/plain; charset=utf-8\n\n{body}"
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(SMTP_USER, [EMAIL_TO], msg.encode("utf-8"))
        logger.info("Email tunnel envoyé à %s", EMAIL_TO)
        return True
    except Exception as e:
        logger.error("Échec envoi email: %s", e)
        return False

def load_sent_urls() -> set:
    try:
        return set(json.loads(open(SENT_URLS_FILE).read()))
    except Exception:
        return set()

def save_sent_urls(urls: set):
    try:
        open(SENT_URLS_FILE, "w").write(json.dumps(list(urls)))
    except Exception:
        pass

def watch_tunnel_url():
    sent_urls = load_sent_urls()
    logger.info("Veilleur tunnel démarré — %d URL déjà notifiées", len(sent_urls))
    while True:
        try:
            if os.path.isfile(TUNNEL_URL_FILE):
                data = json.loads(open(TUNNEL_URL_FILE).read())
                url = data.get("url")
                if url and url not in sent_urls:
                    logger.info("Nouvelle URL tunnel détectée: %s", url)
                    if send_tunnel_email(url):
                        sent_urls.add(url)
                        save_sent_urls(sent_urls)
        except Exception as e:
            logger.error("Erreur watch_tunnel_url: %s", e)
        threading.Event().wait(30)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    t = threading.Thread(target=watch_tunnel_url, daemon=True)
    t.start()
    logger.info("Thread veilleur tunnel démarré")
    yield
    await close_db()

app = FastAPI(
    title="NetAudit API",
    description="Network discovery & security audit platform",
    version="1.0.0",
    lifespan=lifespan,
    default_response_class=JSONResponse,
)

@app.exception_handler(StarletteHTTPException)
@app.exception_handler(RequestValidationError)
async def json_error_handler(request: Request, exc):
    status = getattr(exc, "status_code", 500)
    detail = getattr(exc, "detail", None) or str(exc) or "Internal Server Error"
    if isinstance(exc, RequestValidationError):
        status = 422
        detail = exc.errors()
    return JSONResponse(status_code=status, content={"detail": detail})

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
app.include_router(wifi.router,        prefix="/api/wifi",      tags=["WiFi"])
app.include_router(tools.router,       prefix="/api/tools",     tags=["Tools"])
app.include_router(lanscan.router,     prefix="/api/lanscan",   tags=["LAN Scan"])

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/tunnel-url")
async def tunnel_url():
    if os.path.isfile(TUNNEL_URL_FILE):
        try:
            return json.loads(open(TUNNEL_URL_FILE).read())
        except Exception:
            pass
    return {"url": None, "updated": None}
