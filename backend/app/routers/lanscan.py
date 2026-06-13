from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import asyncio, os, re, ipaddress, socket, struct, subprocess

router = APIRouter()

OUI_DB: dict[str, str] = {
    "00037f": "Cisco",
    "000bdb": "Cisco",
    "0011bc": "Cisco",
    "0012f2": "Cisco",
    "001377": "Cisco",
    "0015c6": "Cisco",
    "0016c8": "Cisco",
    "001a6c": "Cisco",
    "001e4a": "Cisco",
    "0021d8": "Cisco",
    "0026cb": "Cisco",
    "002a10": "Cisco",
    "002bcd": "Cisco",
    "003094": "Cisco",
    "0050f2": "Cisco",
    "00d068": "Cisco",
    "000ec6": "D-Link",
    "0015e9": "D-Link",
    "001b11": "D-Link",
    "002219": "D-Link",
    "080027": "Oracle/VirtualBox",
    "000c29": "VMware",
    "005056": "VMware",
    "001c14": "VMware",
    "000569": "VMware",
    "0050b6": "VMware",
    "0003ff": "Microsoft",
    "0015d2": "Microsoft",
    "001dd8": "Microsoft",
    "0021cc": "Microsoft",
    "001c42": "Parallels",
    "001a11": "Linux",
    "000255": "Linux",
    "0011d8": "Synology",
    "001320": "Synology",
    "001c73": "Synology",
    "000cf1": "Apple",
    "001cb3": "Apple",
    "0026b0": "Apple",
    "00236c": "Atheros",
    "0024b2": "Atheros",
    "000b6b": "ASUS",
    "001e2a": "ASUS",
    "0050e0": "ASUS",
    "001122": "TP-Link",
    "0013c6": "TP-Link",
    "001788": "TP-Link",
    "001a3c": "TP-Link",
    "001e6d": "TP-Link",
    "0021d6": "TP-Link",
    "00253d": "TP-Link",
    "0026ed": "TP-Link",
    "002aa3": "TP-Link",
    "002e8f": "TP-Link",
    "00311c": "TP-Link",
    "0034f7": "TP-Link",
    "00393f": "TP-Link",
    "003e12": "TP-Link",
    "0040f3": "TP-Link",
    "080028": "TP-Link",
    "0c8268": "TP-Link",
    "10fe53": "TP-Link",
    "14cf92": "TP-Link",
    "185472": "TP-Link",
    "1c3b22": "TP-Link",
    "203700": "TP-Link",
    "24b657": "TP-Link",
    "28ee2c": "TP-Link",
    "2c36f8": "TP-Link",
    "2c598a": "TP-Link",
    "305a3a": "TP-Link",
    "342c34": "TP-Link",
    "3822d6": "TP-Link",
    "3c2c30": "TP-Link",
    "3c46d8": "TP-Link",
    "3ca72b": "TP-Link",
    "401632": "TP-Link",
    "40b2c8": "TP-Link",
    "44d1fa": "TP-Link",
    "50c76b": "TP-Link",
    "54af97": "TP-Link",
    "5c4a9e": "TP-Link",
    "640980": "TP-Link",
    "6416f0": "TP-Link",
    "68806a": "TP-Link",
    "6cf049": "TP-Link",
    "70ee50": "TP-Link",
    "7c3981": "TP-Link",
    "7cb177": "TP-Link",
    "843f4e": "TP-Link",
    "842b2b": "TP-Link",
    "8ca048": "TP-Link",
    "909962": "TP-Link",
    "9cb70c": "TP-Link",
    "a0f3c1": "TP-Link",
    "a402b9": "TP-Link",
    "a41f72": "TP-Link",
    "a8bbcf": "TP-Link",
    "ac84c6": "TP-Link",
    "b0a77a": "TP-Link",
    "b09447": "TP-Link",
    "b0be76": "TP-Link",
    "bcd094": "TP-Link",
    "c025e9": "TP-Link",
    "c0c1c0": "TP-Link",
    "c46ab7": "TP-Link",
    "c89b3b": "TP-Link",
    "cc322a": "TP-Link",
    "d058e0": "TP-Link",
    "d08c2b": "TP-Link",
    "d415b3": "TP-Link",
    "d46cbf": "TP-Link",
    "dc092c": "TP-Link",
    "e01276": "TP-Link",
    "e01c41": "TP-Link",
    "e41c4b": "TP-Link",
    "e8b748": "TP-Link",
    "ec6d68": "TP-Link",
    "f05a1b": "TP-Link",
    "f09ce4": "TP-Link",
    "f81f0d": "TP-Link",
    "fc53f3": "TP-Link",
    "00173f": "Netgear",
    "001e4f": "Netgear",
    "00244b": "Netgear",
    "0060b3": "Netgear",
    "080020": "Netgear",
    "084027": "Netgear",
    "0c3946": "Netgear",
    "1c3e84": "Netgear",
    "207a5e": "Netgear",
    "2827bf": "Netgear",
    "2c336c": "Netgear",
    "2c62f4": "Netgear",
    "3055ed": "Netgear",
    "38b12e": "Netgear",
    "3c3718": "Netgear",
    "40a6d9": "Netgear",
    "442ab4": "Netgear",
    "60195c": "Netgear",
    "643150": "Netgear",
    "6805ca": "Netgear",
    "6c198f": "Netgear",
    "785b5d": "Netgear",
    "801f02": "Netgear",
    "8426b6": "Netgear",
    "848479": "Netgear",
    "8ccda8": "Netgear",
    "905694": "Netgear",
    "980ee4": "Netgear",
    "9c9355": "Netgear",
    "a021b7": "Netgear",
    "a03299": "Netgear",
    "a46b5b": "Netgear",
    "ac9e17": "Netgear",
    "b01267": "Netgear",
    "b04e3c": "Netgear",
    "b830a8": "Netgear",
    "bc9a78": "Netgear",
    "c017c5": "Netgear",
    "c0f18b": "Netgear",
    "c878a5": "Netgear",
    "cc7d37": "Netgear",
    "d08cf9": "Netgear",
    "d8d22e": "Netgear",
    "e06995": "Netgear",
    "e0a198": "Netgear",
    "e0f04c": "Netgear",
    "ec2546": "Netgear",
    "f01faf": "Netgear",
    "f45eab": "Netgear",
    "f83dff": "Netgear",
    "fcb693": "Netgear",
    "001e58": "Huawei",
    "00259e": "Huawei",
    "005219": "Huawei",
    "08180e": "Huawei",
    "0c1daf": "Huawei",
    "10567e": "Huawei",
    "107b44": "Huawei",
    "10b5c5": "Huawei",
    "149a1d": "Huawei",
    "14c9c8": "Huawei",
    "18f46a": "Huawei",
    "1c59c0": "Huawei",
    "28a171": "Huawei",
    "44a5d4": "Huawei",
    "481bc0": "Huawei",
    "4cb16b": "Huawei",
    "4ccf67": "Huawei",
    "4ce6a2": "Huawei",
    "58a273": "Huawei",
    "68dfdd": "Huawei",
    "74dbaf": "Huawei",
    "80ab4c": "Huawei",
    "84a8e4": "Huawei",
    "8c28cd": "Huawei",
    "90206a": "Huawei",
    "988217": "Huawei",
    "9cd917": "Huawei",
    "a0e0af": "Huawei",
    "a422b8": "Huawei",
    "ac2ec4": "Huawei",
    "b0966a": "Huawei",
    "b80122": "Huawei",
    "bc2b6b": "Huawei",
    "c0c36b": "Huawei",
    "c44b2a": "Huawei",
    "c8d2c1": "Huawei",
    "ccb7a5": "Huawei",
    "d0e3f1": "Huawei",
    "d4909c": "Huawei",
    "e01d77": "Huawei",
    "e075f7": "Huawei",
    "e0c782": "Huawei",
    "e4c861": "Huawei",
    "ec6819": "Huawei",
    "f42d8e": "Huawei",
    "f8bd09": "Huawei",
    "000fcc": "Samsung",
    "000ff3": "Samsung",
    "00235d": "Samsung",
    "002558": "Samsung",
    "0025a5": "Samsung",
    "0050b8": "Samsung",
    "100a9f": "Samsung",
    "18dbf2": "Samsung",
    "1c66d3": "Samsung",
    "1cb05c": "Samsung",
    "24e6ba": "Samsung",
    "24ec99": "Samsung",
    "28108f": "Samsung",
    "2ccf5f": "Samsung",
    "34a395": "Samsung",
    "3841d7": "Samsung",
    "3c6124": "Samsung",
    "3cbf22": "Samsung",
    "44a34e": "Samsung",
    "44bdcb": "Samsung",
    "48a2e6": "Samsung",
    "4c6b57": "Samsung",
    "4cf77c": "Samsung",
    "50462b": "Samsung",
    "5c49bc": "Samsung",
    "600194": "Samsung",
    "640f28": "Samsung",
    "6c19c0": "Samsung",
    "6cc26b": "Samsung",
    "700a80": "Samsung",
    "78c8e2": "Samsung",
    "78d3b5": "Samsung",
    "7caf4d": "Samsung",
    "8c8315": "Samsung",
    "8c9466": "Samsung",
    "901b0e": "Samsung",
    "944086": "Samsung",
    "9460fe": "Samsung",
    "9c503b": "Samsung",
    "a06986": "Samsung",
    "a08cf8": "Samsung",
    "a489f9": "Samsung",
    "a4d1d2": "Samsung",
    "ac5f3e": "Samsung",
    "b4b5af": "Samsung",
    "b8c403": "Samsung",
    "bcc6db": "Samsung",
    "c86072": "Samsung",
    "cc7a30": "Samsung",
    "d02d27": "Samsung",
    "d45cf2": "Samsung",
    "d895c6": "Samsung",
    "dcd7d1": "Samsung",
    "e08b37": "Samsung",
    "e0ee1b": "Samsung",
    "e49ade": "Samsung",
    "ec2346": "Samsung",
    "ec43f6": "Samsung",
    "fcb86a": "Samsung",
    "fcda1f": "Samsung",
    "fcecda": "Samsung",
    "048c03": "Intel",
    "0c54a5": "Intel",
    "1c1b0d": "Intel",
    "246511": "Intel",
    "28a9f0": "Intel",
    "2cf0ee": "Intel",
    "308d99": "Intel",
    "34e094": "Intel",
    "3ce5a6": "Intel",
    "3cfe95": "Intel",
    "4050e0": "Intel",
    "4497bb": "Intel",
    "4c79ba": "Intel",
    "54049f": "Intel",
    "5c514f": "Intel",
    "6883de": "Intel",
    "6c88d7": "Intel",
    "6cfa5e": "Intel",
    "705a0e": "Intel",
    "78f7be": "Intel",
    "7cebea": "Intel",
    "80629f": "Intel",
    "84a798": "Intel",
    "84c1c1": "Intel",
    "8cde52": "Intel",
    "90675d": "Intel",
    "94c6d1": "Intel",
    "98b8e3": "Intel",
    "98e8fa": "Intel",
    "a04b5c": "Intel",
    "a0b4a5": "Intel",
    "a0c446": "Intel",
    "a49b13": "Intel",
    "a886dd": "Intel",
    "ac16bc": "Intel",
    "b0aa77": "Intel",
    "b4a4e3": "Intel",
    "bc0f2b": "Intel",
    "bc1a67": "Intel",
    "bc2c6b": "Intel",
    "bc9680": "Intel",
    "c02250": "Intel",
    "c096e2": "Intel",
    "c0cb38": "Intel",
    "c4188b": "Intel",
    "c86036": "Intel",
    "cc2d83": "Intel",
    "cc5c75": "Intel",
    "d0c155": "Intel",
    "d40a37": "Intel",
    "d48cb5": "Intel",
    "d4a665": "Intel",
    "d8f2ca": "Intel",
    "dceb2d": "Intel",
    "e0071b": "Intel",
    "e04b3c": "Intel",
    "e0c97a": "Intel",
    "e4a471": "Intel",
    "e8d0fc": "Intel",
    "ece09b": "Intel",
    "f099bf": "Intel",
    "f0def1": "Intel",
    "f40269": "Intel",
    "f4e4ad": "Intel",
    "f80cf3": "Intel",
    "fc626b": "Intel",
    "fc753d": "Intel",
    "fc9902": "Intel",
    "b8a386": "Raspberry Pi",
    "b853ac": "Raspberry Pi",
    "d83add": "Raspberry Pi",
    "dc312e": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
}

def _ip_to_network(ip: str) -> dict | None:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            prefix = 8
        elif first == 172 and 16 <= second <= 31:
            prefix = 12
        elif first == 192 and second == 168:
            prefix = 24
        elif first == 100 and 64 <= second <= 127:
            prefix = 10
        else:
            prefix = 24
        nw = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return {"ip": ip, "prefix": prefix, "network": str(nw), "netmask": str(nw.netmask)}
    except Exception:
        return None


def _vendor(mac: str) -> str:
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    return OUI_DB.get(oui, "") if oui else ""


def _mac_to_str(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


async def _run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return -1, "", f"Timeout après {timeout}s"
        return proc.returncode or 0, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return -1, "", f"Commande non trouvée: {cmd[0]}"


def _get_local_networks() -> list[dict]:
    networks = []
    seen_ips = set()

    for method in ["ip", "hostname", "fib"]:
        try:
            if method == "ip":
                out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True, timeout=5)
                for line in out.splitlines():
                    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                    if m:
                        ip = m.group(1)
                        prefix = int(m.group(2))
                        if not ip.startswith("127.") and ip not in seen_ips:
                            seen_ips.add(ip)
                            nw = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                            networks.append({"ip": ip, "prefix": prefix, "network": str(nw), "netmask": str(nw.netmask)})

            elif method == "hostname":
                out = subprocess.check_output(["hostname", "-I"], text=True, timeout=5)
                for ip in out.strip().split():
                    ip = ip.strip()
                    if ip and not ip.startswith("127.") and ip not in seen_ips:
                        seen_ips.add(ip)
                        nw = _ip_to_network(ip)
                        if nw:
                            networks.append(nw)

            elif method == "fib":
                with open("/proc/net/fib_trie") as f:
                    content = f.read()
                for m in re.finditer(r"LOCAL\s*\n\s*\|-- (\d+\.\d+\.\d+\.\d+)", content):
                    ip = m.group(1)
                    if not ip.startswith("127.") and ip not in seen_ips:
                        seen_ips.add(ip)
                        nw = _ip_to_network(ip)
                        if nw:
                            networks.append(nw)
        except Exception:
            continue

        if networks:
            break

    if not networks:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if not ip.startswith("127."):
                parts = ip.split(".")
                nw = ipaddress.IPv4Network(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", strict=False)
                networks.append({"ip": ip, "prefix": 24, "network": str(nw), "netmask": "255.255.255.0"})
        except Exception:
            networks.append({"ip": "127.0.0.1", "prefix": 8, "network": "127.0.0.0/8", "netmask": "255.0.0.0"})

    return networks


def _parse_arp_table() -> list[dict]:
    devices = []
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    ip = parts[0]
                    hw = parts[3]
                    devices.append({
                        "ip": ip,
                        "mac": hw,
                        "vendor": _vendor(hw),
                        "hostname": "",
                        "status": "reachable",
                        "source": "arp_cache",
                    })
    except Exception:
        pass
    return devices


async def _scan_via_tool() -> list[dict]:
    for tool, args in [
        ("arp-scan", ["arp-scan", "--localnet", "--retry=2", "-x", "-q"]),
        ("nmap", ["nmap", "-sn", "-n", "-T5", "--disable-arp-ping"]),
    ]:
        code, out, err = await _run_cmd(["which", tool], timeout=5)
        if code != 0:
            code, out, err = await _run_cmd([tool, "--version"], timeout=5)
        if code != 0:
            continue

        networks = _get_local_networks()
        if not networks:
            return []

        all_devices = []
        for net in networks:
            net_str = net["network"]
            if net_str.startswith("127.") or net_str.startswith("172."):
                continue

            try:
                n = ipaddress.IPv4Network(net_str, strict=False)
                if n.num_addresses > 512:
                    n = n.supernet(new_prefix=24) if n.prefixlen < 24 else n
                    net_str = str(n)
            except Exception:
                pass

            if tool == "arp-scan":
                cmd = args
            else:
                cmd = [tool, "-sn", "-n", "-T4", net_str]

            rc, stdout, stderr = await _run_cmd(cmd, timeout=180)

            if tool == "arp-scan":
                for line in stdout.splitlines():
                    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).lower()
                        desc = m.group(3).strip()
                        vendor = _vendor(mac) or desc
                        all_devices.append({
                            "ip": ip, "mac": mac, "vendor": vendor,
                            "hostname": "", "status": "up", "source": "arp-scan",
                        })
            elif tool == "nmap":
                current_ip = ""
                for line in stdout.splitlines():
                    m = re.match(r"Nmap scan report for (\S+)", line)
                    if m:
                        current_ip = m.group(1).strip("()")
                        current_ip = re.sub(r"[()]", "", current_ip)
                    m = re.match(r"MAC Address:\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
                    if m:
                        mac = m.group(1).lower()
                        desc = m.group(2).strip()
                        vendor = _vendor(mac) or desc
                        hostname = ""
                        if current_ip:
                            try:
                                hostname = socket.gethostbyaddr(current_ip)[0]
                            except Exception:
                                pass
                        all_devices.append({
                            "ip": current_ip, "mac": mac, "vendor": vendor,
                            "hostname": hostname, "status": "up", "source": "nmap",
                        })

        if all_devices:
            return all_devices

        if tool == "nmap":
            for line in stdout.splitlines():
                m = re.match(r"Nmap scan report for (\S+)", line)
                if m:
                    ip_candidate = m.group(1).strip("()")
                    all_devices.append({
                        "ip": ip_candidate, "mac": "", "vendor": "",
                        "hostname": "", "status": "up", "source": "nmap_ping",
                    })
            return all_devices

    return []


async def _scan_python() -> list[dict]:
    networks = _get_local_networks()
    if not networks:
        return _parse_arp_table()

    all_devices = []
    seen = set()

    for net_info in networks:
        net_str = net_info["network"]
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
        except Exception:
            continue

        host_list = list(net.hosts())
        if len(host_list) > 254:
            host_list = host_list[:254]

        addrs = []
        for host in host_list:
            addrs.append(host)
            if len(addrs) >= 100:
                break

        sem = asyncio.Semaphore(30)
        async def limited_ping(ip: str) -> tuple[str, str]:
            async with sem:
                return await _ping_host(ip)
        tasks = [limited_ping(str(a)) for a in addrs]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, r in enumerate(results):
            if isinstance(r, Exception) or not r:
                continue
            ip_str, mac = r
            if ip_str and ip_str not in seen:
                seen.add(ip_str)
                vendor = _vendor(mac) if mac else ""
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    pass
                all_devices.append({
                    "ip": ip_str,
                    "mac": mac or "",
                    "vendor": vendor or "",
                    "hostname": hostname or "",
                    "status": "up",
                    "source": "ping" if mac else "ping_no_mac",
                })

    arp_devices = _parse_arp_table()
    for d in arp_devices:
        if d["ip"] not in seen:
            seen.add(d["ip"])
            all_devices.append(d)

    return all_devices


async def _ping_host(ip: str) -> tuple[str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "2", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=3)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return "", ""
        if rc != 0:
            return "", ""
    except FileNotFoundError:
        return "", ""

    mac = ""
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3] if parts[3] != "00:00:00:00:00:00" else ""
                    break
    except Exception:
        pass

    return ip, mac


@router.get("/status")
async def lanscan_status():
    tools = {}
    for t in ["arp-scan", "nmap", "ping"]:
        code, _, _ = await _run_cmd(["which", t], timeout=3)
        tools[t] = code == 0

    networks = _get_local_networks()

    return {
        "tools": tools,
        "networks": networks,
        "interface_count": len(networks),
    }


@router.get("/scan")
async def lanscan_scan():
    devices = await _scan_via_tool()
    if not devices:
        devices = await _scan_python()

    if not devices:
        devices = _parse_arp_table()

    arp_devices = _parse_arp_table()
    arp_by_ip = {d["ip"]: d for d in arp_devices}
    for d in devices:
        if d["ip"] in arp_by_ip and not d.get("mac"):
            d["mac"] = arp_by_ip[d["ip"]]["mac"]
            d["vendor"] = arp_by_ip[d["ip"]]["vendor"] or d["vendor"]

    networks = _get_local_networks()

    return {
        "devices": devices,
        "count": len(devices),
        "networks": networks,
        "scanner": "tool" if devices and any(d.get("source") in ("arp-scan", "nmap") for d in devices) else "python",
    }
