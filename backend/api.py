from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Optional
import subprocess
import shlex
import asyncio
import shutil
import traceback
import os
import uuid

app = FastAPI(title="Nmap API")

# Global in-memory job store
JOBS = {}

# Retrieve API key if defined (for cloud deployments)
NMAP_API_KEY = os.environ.get("NMAP_API_KEY", "").strip()

async def check_api_key(request: Request):
    if NMAP_API_KEY:
        header_key = request.headers.get("X-API-Key", "").strip()
        if header_key != NMAP_API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API key")

class CORSEverywhere(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            response = JSONResponse({})
        else:
            response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
        return response

app.add_middleware(CORSEverywhere)


class NmapRequest(BaseModel):
    target: str = ""

    # === SCAN TYPES ===
    syn_scan: bool = False          # -sS
    tcp_connect: bool = False       # -sT
    udp_scan: bool = False          # -sU
    null_scan: bool = False         # -sN
    fin_scan: bool = False          # -sF
    xmas_scan: bool = False         # -sX
    ack_scan: bool = False          # -sA
    window_scan: bool = False       # -sW
    ip_protocol_scan: bool = False  # -sO
    rpc_scan: bool = False          # -sR

    # === DISCOVERY ===
    ping_sweep: bool = False        # -sn
    no_ping: bool = False           # -Pn
    syn_ping: bool = False          # -PS
    ack_ping: bool = False          # -PA
    udp_ping: bool = False          # -PU
    sctp_ping: bool = False         # -PY
    icmp_echo: bool = False         # -PE
    icmp_timestamp: bool = False    # -PP
    icmp_mask: bool = False         # -PM
    ip_proto_ping: bool = False     # -PO
    arp_ping: bool = False          # -PR
    traceroute: bool = False        # --traceroute
    force_rdns: bool = False        # -R
    disable_rdns: bool = False      # -n
    system_dns: bool = False        # --system-dns
    list_scan: bool = False         # -sL

    # === SERVICE/OS ===
    service_detection: bool = False      # -sV
    version_trace: bool = False          # --version-trace
    os_detection: bool = False           # -O
    os_scan_guess: bool = False          # --osscan-guess
    aggressive_scan: bool = False        # -A
    script_scan: bool = False            # -sC

    # === PORT OPTIONS ===
    fast_scan: bool = False         # -F
    all_ports: bool = False         # -p 1-65535
    sequential: bool = False        # -r
    ipv6: bool = False              # -6
    port_range: str = ""            # -p [range]
    top_ports: str = ""             # --top-ports [N]

    # === EVASION ===
    fragment: bool = False          # -f
    badsum: bool = False            # --badsum
    randomize_hosts: bool = False   # --randomize-hosts
    send_eth: bool = False          # --send-eth
    send_ip: bool = False           # --send-ip
    defeat_rst: bool = False        # --defeat-rst-ratelimit
    open_only: bool = False         # --open
    reason: bool = False            # --reason
    packet_trace: bool = False      # --packet-trace
    verbose: bool = False           # -v
    debug: bool = False             # -d

    # --- value-based evasion ---
    mtu: str = ""                   # --mtu [val]
    decoy: str = ""                 # -D RND:[n] or -D [ip,ip]
    idle_zombie: str = ""           # -sI [zombie]
    source_port: str = ""           # --source-port [port]
    data_length: str = ""           # --data-length [size]
    spoof_mac: str = ""             # --spoof-mac [mac|0|vendor]
    dns_servers: str = ""           # --dns-servers [servers]
    scan_flags: str = ""            # --scanflags [flags]
    interface: str = ""             # -e [iface]
    script: str = ""                # --script [name]
    script_trace: bool = False      # --script-trace
    exclude: str = ""               # --exclude [targets]
    iR: str = ""                    # -iR [number]

    # === TIMING ===
    timing: str = "3"               # -T[0-5]
    ttl: str = ""                   # --ttl [time]
    min_parallelism: str = ""       # --min-parallelism
    max_parallelism: str = ""       # --max-parallelism
    min_hostgroup: str = ""         # --min-hostgroup
    max_hostgroup: str = ""         # --max-hostgroup
    max_rtt_timeout: str = ""       # --max-rtt-timeout
    initial_rtt_timeout: str = ""   # --initial-rtt-timeout
    max_retries: str = ""           # --max-retries
    host_timeout: str = ""          # --host-timeout
    scan_delay: str = ""            # --scan-delay
    max_scan_delay: str = ""        # --max-scan-delay
    min_rate: str = ""              # --min-rate
    max_rate: str = ""              # --max-rate

    # === CUSTOM ===
    custom_flags: str = ""

    # === OUTPUT ===
    version_intensity: str = ""   # --version-intensity [0-9]
    out_normal: str = ""          # -oN [file]
    out_xml: str = ""             # -oX [file]
    out_grep: str = ""            # -oG [file]
    out_all: str = ""             # -oA [basename]
    stats_every: str = ""         # --stats-every [time]
    iflist: bool = False          # --iflist

def get_nmap_path():
    # Reload PATH from Windows registry so freshly installed nmap is found (Windows only)
    try:
        import winreg
        import ctypes
        machine_path = winreg.QueryValueEx(
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
            "Path")[0]
        user_path = winreg.QueryValueEx(
            winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Environment"),
            "Path")[0]
        os.environ["PATH"] = machine_path + ";" + user_path + ";" + os.environ.get("PATH","")
    except (ImportError, Exception):
        pass

    paths = [
        "nmap",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    for p in paths:
        # Try shutil.which first
        found = shutil.which(p)
        if found:
            return found
        # Try direct path existence
        if os.path.isfile(p):
            return p
    return None

def build_cmd(nmap_path: str, req: NmapRequest) -> list:
    cmd = [nmap_path]

    # IPv6
    if req.ipv6: cmd.append("-6")

    # ── RULE: -sL (list scan) is incompatible with everything else ──
    if req.list_scan:
        cmd.append("-sL")
        if req.verbose: cmd.append("-v")
        if req.timing:  cmd.append(f"-T{req.timing}")
        if req.target:  cmd.append(req.target)
        return cmd

    # ── RULE: -sn (ping sweep) cannot mix with port/service scan options ──
    if req.ping_sweep:
        cmd.append("-sn")
        if req.no_ping:        cmd.append("-Pn")
        if req.syn_ping:       cmd.append("-PS")
        if req.ack_ping:       cmd.append("-PA")
        if req.udp_ping:       cmd.append("-PU")
        if req.sctp_ping:      cmd.append("-PY")
        if req.icmp_echo:      cmd.append("-PE")
        if req.icmp_timestamp: cmd.append("-PP")
        if req.icmp_mask:      cmd.append("-PM")
        if req.ip_proto_ping:  cmd.append("-PO")
        if req.arp_ping:       cmd.append("-PR")
        if req.traceroute:     cmd.append("--traceroute")
        if req.timing:         cmd.append(f"-T{req.timing}")
        if req.verbose:        cmd.append("-v")
        if req.target:         cmd.append(req.target)
        return cmd

    # --- Primary TCP scan type: pick only ONE ---
    if req.idle_zombie:        cmd.extend(["-sI", req.idle_zombie])
    elif req.syn_scan:         cmd.append("-sS")
    elif req.tcp_connect:      cmd.append("-sT")
    elif req.null_scan:        cmd.append("-sN")
    elif req.fin_scan:         cmd.append("-sF")
    elif req.xmas_scan:        cmd.append("-sX")
    elif req.ack_scan:         cmd.append("-sA")
    elif req.window_scan:      cmd.append("-sW")
    elif req.ip_protocol_scan: cmd.append("-sO")
    elif req.rpc_scan:         cmd.append("-sR")

    # UDP can always stack alongside a TCP scan type
    if req.udp_scan: cmd.append("-sU")

    # --- Discovery / Pings ---
    if req.no_ping:        cmd.append("-Pn")
    if req.syn_ping:       cmd.append("-PS")
    if req.ack_ping:       cmd.append("-PA")
    if req.udp_ping:       cmd.append("-PU")
    if req.sctp_ping:      cmd.append("-PY")
    if req.icmp_echo:      cmd.append("-PE")
    if req.icmp_timestamp: cmd.append("-PP")
    if req.icmp_mask:      cmd.append("-PM")
    if req.ip_proto_ping:  cmd.append("-PO")
    if req.arp_ping:       cmd.append("-PR")
    # -R and -n are mutually exclusive
    if req.force_rdns:     cmd.append("-R")
    elif req.disable_rdns: cmd.append("-n")
    if req.system_dns:     cmd.append("--system-dns")
    if req.traceroute:     cmd.append("--traceroute")
    if req.dns_servers:    cmd.extend(["--dns-servers", req.dns_servers])

    # --- Service / OS / Scripts ---
    if req.service_detection: cmd.append("-sV")
    if req.version_trace:     cmd.append("--version-trace")
    if req.version_intensity: cmd.extend(["--version-intensity", req.version_intensity])
    if req.os_detection:      cmd.append("-O")
    if req.os_scan_guess:     cmd.append("--osscan-guess")
    if req.aggressive_scan:   cmd.append("-A")
    if req.script_scan:       cmd.append("-sC")
    if req.script:
        cmd.extend(["--script", req.script])
        if req.script_trace: cmd.append("--script-trace")

    # --- Port options ---
    if req.fast_scan:  cmd.append("-F")
    if req.sequential: cmd.append("-r")
    if req.all_ports:
        cmd.extend(["-p", "1-65535"])
    elif req.port_range:
        cmd.extend(["-p", req.port_range])
    if req.top_ports:  cmd.extend(["--top-ports", req.top_ports])
    if req.scan_flags: cmd.extend(["--scanflags", req.scan_flags])

    # --- Evasion ---
    if req.fragment: cmd.append("-f")
    if req.mtu: cmd.extend(["--mtu", req.mtu])
    if req.decoy: cmd.extend(["-D", req.decoy])
    if req.source_port: cmd.extend(["--source-port", req.source_port])
    if req.data_length: cmd.extend(["--data-length", req.data_length])
    if req.randomize_hosts: cmd.append("--randomize-hosts")
    if req.spoof_mac: cmd.extend(["--spoof-mac", req.spoof_mac])
    if req.badsum: cmd.append("--badsum")
    if req.send_eth: cmd.append("--send-eth")
    if req.send_ip: cmd.append("--send-ip")
    if req.defeat_rst: cmd.append("--defeat-rst-ratelimit")
    if req.interface: cmd.extend(["-e", req.interface])
    if req.iR: cmd.extend(["-iR", req.iR])
    if req.exclude: cmd.extend(["--exclude", req.exclude])

    # --- Output / Debug ---
    if req.verbose:        cmd.append("-v")
    if req.debug:          cmd.append("-d")
    if req.reason:         cmd.append("--reason")
    if req.open_only:      cmd.append("--open")
    if req.packet_trace:   cmd.append("--packet-trace")
    if req.iflist:         cmd.append("--iflist")
    if req.out_normal:     cmd.extend(["-oN", req.out_normal])
    if req.out_xml:        cmd.extend(["-oX", req.out_xml])
    if req.out_grep:       cmd.extend(["-oG", req.out_grep])
    if req.out_all:        cmd.extend(["-oA", req.out_all])
    if req.stats_every:    cmd.extend(["--stats-every", req.stats_every])

    # --- Timing ---
    if req.timing: cmd.append(f"-T{req.timing}")
    if req.ttl: cmd.extend(["--ttl", req.ttl])
    if req.min_parallelism: cmd.extend(["--min-parallelism", req.min_parallelism])
    if req.max_parallelism: cmd.extend(["--max-parallelism", req.max_parallelism])
    if req.min_hostgroup: cmd.extend(["--min-hostgroup", req.min_hostgroup])
    if req.max_hostgroup: cmd.extend(["--max-hostgroup", req.max_hostgroup])
    if req.max_rtt_timeout: cmd.extend(["--max-rtt-timeout", req.max_rtt_timeout])
    if req.initial_rtt_timeout: cmd.extend(["--initial-rtt-timeout", req.initial_rtt_timeout])
    if req.max_retries: cmd.extend(["--max-retries", req.max_retries])
    if req.host_timeout: cmd.extend(["--host-timeout", req.host_timeout])
    if req.scan_delay: cmd.extend(["--scan-delay", req.scan_delay])
    if req.max_scan_delay: cmd.extend(["--max-scan-delay", req.max_scan_delay])
    if req.min_rate: cmd.extend(["--min-rate", req.min_rate])
    if req.max_rate: cmd.extend(["--max-rate", req.max_rate])

    # --- Custom ---
    if req.custom_flags:
        cmd.extend(shlex.split(req.custom_flags))

    # --- Target ---
    if req.target:
        cmd.append(req.target)

    return cmd

from fastapi import Depends

@app.get("/health")
async def health_check():
    return {"status": "online", "nmap_found": get_nmap_path() is not None}

@app.post("/api/scan")
async def run_scan(req: NmapRequest, background_tasks: BackgroundTasks, _ = Depends(check_api_key)):
    try:
        job_id = str(uuid.uuid4())
        nmap_path = get_nmap_path()
        cmd = build_cmd(nmap_path if nmap_path else "nmap", req)

        if not nmap_path:
            return {
                "job_id": job_id,
                "status": "mock",
                "command": " ".join(cmd),
                "output": (
                    f"[MOCK MODE] Nmap not found on system.\n"
                    f"Would have executed: {' '.join(cmd)}\n\n"
                    f"Host: {req.target or '(none)'}\n"
                    f"Status: Up\nPorts: 22/tcp open ssh, 80/tcp open http, 443/tcp open https\n"
                    f"Service: OpenSSH 8.9, Apache 2.4.54\n"
                ),
                "error": "Nmap not installed. Install from https://nmap.org/download"
            }

        JOBS[job_id] = {
            "status": "running",
            "command": " ".join(cmd),
            "output": "",
            "error": ""
        }

        background_tasks.add_task(execute_scan, job_id, cmd)
        return {"job_id": job_id}

    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"{str(e)}\n{traceback.format_exc()}")

async def execute_scan(job_id: str, cmd: list):
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        JOBS[job_id]["status"] = "completed"
        JOBS[job_id]["output"] = stdout.decode(errors="replace")
        JOBS[job_id]["error"] = stderr.decode(errors="replace")
    except Exception as e:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["error"] = f"{str(e)}\n{traceback.format_exc()}"

@app.get("/api/scan/{job_id}")
async def get_scan_status(job_id: str, _ = Depends(check_api_key)):
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
    return JOBS[job_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
