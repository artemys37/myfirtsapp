from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import asyncio, os, re, json
from pathlib import Path
from datetime import datetime, timezone

router = APIRouter()

TOOLS_OUTPUT_DIR = "/tmp/tools_output"

def ensure_output_dir():
    Path(TOOLS_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

def tool_path(name: str) -> str | None:
    for d in os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin").split(":"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None

async def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return -1, "", f"Timeout après {timeout}s"
        return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return -1, "", f"Outil non installé: {cmd[0]}"

class NmapRequest(BaseModel):
    target: str
    ports: str = "22,80,443,8080"
    flags: str = "-sV -T4"

class NiktoRequest(BaseModel):
    url: str

class GobusterRequest(BaseModel):
    url: str
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"

class HydraRequest(BaseModel):
    host: str
    port: int
    service: str
    username: str
    password_list: str

class HashRequest(BaseModel):
    hash: str
    hash_type: str = "raw-md5"
    wordlist: str = "/usr/share/wordlists/rockyou.txt"

class ArchiveRequest(BaseModel):
    filepath: str
    password: Optional[str] = None

class TsharkRequest(BaseModel):
    pcap_path: str
    filter: Optional[str] = None

@router.get("/check")
async def check_tools():
    tools = ["nmap", "nikto", "gobuster", "hydra", "john", "hashcat", "7z", "tshark", "sqlmap", "dirb", "aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng", "kismet", "wifite"]
    result = {}
    for t in tools:
        p = tool_path(t)
        result[t] = {"installed": p is not None, "path": p}
    return result

@router.post("/nmap/run")
async def run_nmap(req: NmapRequest, background_tasks: BackgroundTasks):
    p = tool_path("nmap")
    if not p:
        raise HTTPException(400, "Nmap non installé")
    ensure_output_dir()
    outfile = os.path.join(TOOLS_OUTPUT_DIR, f"nmap_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt")
    cmd = [p, *req.flags.split(), "-p", req.ports, req.target, "-oN", outfile]
    code, out, err = await run_cmd(cmd, timeout=300)
    output_text = f"[COMMANDE]\n{' '.join(cmd)}\n\n[SORTIE]\n{out}\n{err}"
    if os.path.isfile(outfile):
        with open(outfile) as f:
            output_text += f"\n\n[FICHIER]\n{f.read()}"
    return {"exit_code": code, "output": output_text}

@router.post("/nikto/run")
async def run_nikto(req: NiktoRequest):
    p = tool_path("nikto")
    if not p:
        raise HTTPException(400, "Nikto non installé")
    cmd = ["perl", p, "-h", req.url, "-C", "all", "-nointeractive"]
    code, out, err = await run_cmd(cmd, timeout=180)
    return {"exit_code": code, "output": out + "\n" + err}

@router.post("/gobuster/run")
async def run_gobuster(req: GobusterRequest):
    p = tool_path("gobuster")
    if not p:
        raise HTTPException(400, "Gobuster non installé")
    wordlist = req.wordlist
    if not os.path.isfile(wordlist):
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.isfile(wordlist):
            wordlist = "/usr/share/dirb/wordlists/common.txt"
    cmd = [p, "dir", "-u", req.url, "-w", wordlist, "-q"]
    code, out, err = await run_cmd(cmd, timeout=180)
    return {"exit_code": code, "output": out + "\n" + err}

@router.post("/hydra/run")
async def run_hydra(req: HydraRequest):
    p = tool_path("hydra")
    if not p:
        return {"exit_code": -1, "output": "Hydra n'est pas installé sur ce serveur.\nUtilisez la page Auth Tests (Tests d'authentification) pour les tests de bruteforce.\n\nServices disponibles via Auth Tests:\n- SSH (22)\n- FTP (21)\n- HTTP Basic Auth (80/443)\n- Telnet (23)\n- SMB (445)\n- RDP (3389)"}
    passfile = os.path.join(TOOLS_OUTPUT_DIR, "hydra_pass.txt")
    Path(passfile).write_text(req.password_list)
    cmd = [p, "-l", req.username, "-P", passfile, f"-s{req.port}", req.host, req.service]
    code, out, err = await run_cmd(cmd, timeout=180)
    return {"exit_code": code, "output": out + "\n" + err}

@router.post("/john/run")
async def run_john(req: HashRequest):
    p = tool_path("john")
    if p:
        ensure_output_dir()
        hashfile = os.path.join(TOOLS_OUTPUT_DIR, "john_hash.txt")
        Path(hashfile).write_text(req.hash)
        cmd = [p, f"--format={req.hash_type}", hashfile, f"--wordlist={req.wordlist}", "--pot=" + os.path.join(TOOLS_OUTPUT_DIR, "john.pot")]
        code, out, err = await run_cmd(cmd, timeout=120)
        show_cmd = [p, "--show", f"--format={req.hash_type}", hashfile, "--pot=" + os.path.join(TOOLS_OUTPUT_DIR, "john.pot")]
        _, show_out, _ = await run_cmd(show_cmd, timeout=10)
        return {"exit_code": code, "output": out + "\n" + err + "\n\n[RÉSULTATS]\n" + show_out}
    else:
        return await _py_hash_crack(req, "john")

@router.post("/hashcat/run")
async def run_hashcat(req: HashRequest):
    return await _py_hash_crack(req, "hashcat")

import hashlib

async def _py_hash_crack(req: HashRequest, tool: str):
    hash_algo = req.hash_type.lower().replace("-", "").replace("_", "")
    target = req.hash.strip()
    wordlist_path = req.wordlist if os.path.isfile(req.wordlist) else None

    words = ["password", "123456", "admin", "welcome", "qwerty", "letmein", "monkey", "dragon", "master", "passw0rd"]

    result = f"⚠️ {tool.title()} non installé — fallback Python\n"
    result += f"Hash: {target[:60]}...\nFormat: {req.hash_type}\n\n"
    result += "Mots de passe testés:\n"

    found = None
    for w in words:
        if hash_algo in ("rawmd5", "md5", "0"):
            h = hashlib.md5(w.encode()).hexdigest()
        elif hash_algo in ("rawsha1", "sha1", "100"):
            h = hashlib.sha1(w.encode()).hexdigest()
        elif hash_algo in ("rawsha256", "sha256", "1400"):
            h = hashlib.sha256(w.encode()).hexdigest()
        elif hash_algo in ("rawsha512", "sha512", "1700"):
            h = hashlib.sha512(w.encode()).hexdigest()
        else:
            h = hashlib.sha256(w.encode()).hexdigest()

        result += f"  {w} → {h[:16]}...\n"
        if h == target:
            found = w

    if found:
        result += f"\n✅ Mot de passe trouvé: {found}\n"
    else:
        result += "\n❌ Aucun mot de passe trouvé dans la liste de test\n"
        result += "Conseil: Installez john/hashcat ou utilisez une wordlist plus volumineuse.\n"

    return {"exit_code": 0 if found else 1, "output": result}

@router.post("/7z/run")
async def run_7z(req: ArchiveRequest):
    p = tool_path("7z")
    if not p:
        raise HTTPException(400, "7-Zip non installé")
    if not os.path.isfile(req.filepath):
        raise HTTPException(400, f"Fichier introuvable: {req.filepath}")
    if req.password:
        cmd = [p, "t", req.filepath, f"-p{req.password}"]
    else:
        cmd = [p, "l", req.filepath]
    code, out, err = await run_cmd(cmd, timeout=60)
    return {"exit_code": code, "output": out + "\n" + err}

@router.post("/tshark/analyze")
async def analyze_pcap(req: TsharkRequest):
    p = tool_path("tshark")
    if not p:
        raise HTTPException(400, "TShark non installé")
    if not os.path.isfile(req.pcap_path):
        raise HTTPException(400, f"PCAP introuvable: {req.pcap_path}")
    if req.filter:
        cmd = [p, "-r", req.pcap_path, "-Y", req.filter, "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol", "-e", "frame.len"]
    else:
        cmd = [p, "-r", req.pcap_path, "-z", "conv,tcp", "-z", "io,stat,1"]
    code, out, err = await run_cmd(cmd, timeout=60)
    return {"exit_code": code, "output": out + "\n" + err}

@router.get("/wordlists")
async def list_wordlists():
    paths = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/dirb/wordlists/big.txt",
        "/usr/share/nmap/nmap-services",
        "/opt/nikto/program/databases/",
    ]
    result = {}
    for p in paths:
        result[p] = os.path.isfile(p) if not p.endswith("/") else os.path.isdir(p)
    return result
