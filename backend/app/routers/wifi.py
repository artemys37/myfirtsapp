from fastapi import APIRouter, HTTPException
import asyncio, os, re, csv, io

router = APIRouter()

WIFI_CONFIG_PATHS = [
    "/etc/NetworkManager/system-connections/",
    "/etc/wpa_supplicant/",
    "/etc/wpa_supplicant/wpa_supplicant.conf",
    "/var/lib/wpa_supplicant/",
]

async def _run(cmd: str) -> tuple[str, str]:
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return stdout.decode().strip(), stderr.decode().strip()

async def _check_wifi_hw() -> dict:
    out, _ = await _run("iw dev 2>/dev/null")
    if out:
        interfaces = []
        for line in out.split("\n"):
            m = re.match(r"Interface\s+(\S+)", line)
            if m:
                interfaces.append(m.group(1))
        return {"available": True, "interfaces": interfaces}
    return {"available": False, "interfaces": []}

@router.get("/status")
async def wifi_status():
    hw = await _check_wifi_hw()
    saved_files = []
    for path in WIFI_CONFIG_PATHS:
        if os.path.isdir(path):
            saved_files.extend([
                f for f in os.listdir(path)
                if f.endswith(".nmconnection") or f == "wpa_supplicant.conf"
            ])
        elif os.path.isfile(path):
            saved_files.append(path)
    return {
        "hardware": hw,
        "saved_configs": len(saved_files),
        "tools": {
            "iw": bool((await _run("which iw 2>/dev/null"))[0]),
            "nmcli": bool((await _run("which nmcli 2>/dev/null"))[0]),
            "airodump": bool((await _run("which airodump-ng 2>/dev/null"))[0]),
        },
    }

@router.get("/scan")
async def wifi_scan():
    hw = await _check_wifi_hw()
    if not hw["available"]:
        return {"networks": [], "count": 0, "note": "Aucune interface WiFi disponible sur ce serveur"}

    networks = []
    out, err = await _run("iw dev " + hw["interfaces"][0] + " scan 2>/dev/null")
    if not out:
        out, err = await _run("nmcli -t -f ssid,bssid,signal,security,chan dev wifi 2>/dev/null")

    current = {}
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("BSS "):
            if current and current.get("ssid"):
                networks.append(current)
            current = {"bssid": line.split("(")[0].replace("BSS ", "").strip()}
        elif "SSID:" in line:
            current["ssid"] = line.split("SSID:")[-1].strip()
        elif "freq:" in line:
            current["freq"] = line.split("freq:")[-1].strip()
        elif "signal:" in line:
            m = re.search(r"[-0-9.]+", line)
            current["signal"] = float(m.group()) if m else 0
        elif "WPA:" in line or "RSN:" in line or "WPA" in line:
            current["encryption"] = "WPA2/WPA3"
        elif "WEP:" in line:
            current["encryption"] = "WEP"
        elif "capabilities:" in line and "0x" in line:
            if "encryption" not in current:
                current["encryption"] = "OPEN"

    if current and current.get("ssid"):
        networks.append(current)

    if not networks:
        out2, _ = await _run("nmcli -t -f ssid,bssid,signal,security,chan dev wifi 2>/dev/null")
        for line in out2.split("\n"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[0]:
                networks.append({
                    "ssid": parts[0],
                    "bssid": parts[1],
                    "signal": int(parts[2]) if parts[2].isdigit() else 0,
                    "encryption": parts[3],
                    "chan": parts[4] if len(parts) > 4 else "",
                })

    return {"networks": networks, "count": len(networks)}

@router.get("/saved")
async def wifi_saved():
    passwords = []
    seen = set()

    for path in WIFI_CONFIG_PATHS:
        if os.path.isdir(path):
            for fname in os.listdir(path):
                fpath = os.path.join(path, fname)
                if fname.endswith(".nmconnection"):
                    try:
                        with open(fpath) as f:
                            content = f.read()
                        ssid_m = re.search(r"^ssid=(.+)", content, re.M)
                        psk_m = re.search(r"^psk=(.+)", content, re.M)
                        ssid = ssid_m.group(1) if ssid_m else fname.replace(".nmconnection", "")
                        if ssid not in seen:
                            seen.add(ssid)
                            passwords.append({
                                "ssid": ssid,
                                "password": psk_m.group(1) if psk_m else "",
                                "source": fpath,
                            })
                    except Exception:
                        pass
        elif os.path.isfile(path) and "wpa_supplicant" in path:
            try:
                with open(path) as f:
                    content = f.read()
                for m in re.finditer(r'network=\{\s*ssid="([^"]+)"[^}]*psk="([^"]*)"', content):
                    if m.group(1) not in seen:
                        seen.add(m.group(1))
                        passwords.append({
                            "ssid": m.group(1),
                            "password": m.group(2),
                            "source": path,
                        })
            except Exception:
                pass

    return {"saved": passwords, "count": len(passwords)}
