#!/usr/bin/env python3
import platform, subprocess, shutil, json, argparse

def run_cmd(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def parse_lsof(out: str, proto: str):
    socks = []
    lines = out.splitlines()
    if not lines:
        return socks
    # header: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        cmd, pid, user = parts[0], parts[1], parts[2]
        name = parts[-1]  # e.g. *:7000 or 127.0.0.1:5432 or [::1]:8000
        if ":" not in name:
            continue
        ip, port_s = name.rsplit(":", 1)
        ip = ip.strip("[]")
        fam = "ipv6" if (":" in ip and ip.count(".") == 0) else "ipv4"
        if ip == "*":
            ip = "::" if fam == "ipv6" else "0.0.0.0"
        try:
            port = int(port_s)
        except ValueError:
            continue
        socks.append({
            "ip": ip, "port": port, "pid": pid, "process": cmd, "user": user,
            "proto": proto, "family": fam
        })
    return socks

def list_ports_macos(use_sudo=False):
    if not shutil.which("lsof"):
        return []
    base = (["sudo"] if use_sudo else []) + ["lsof", "-nP"]
    socks = []
    # TCP LISTEN
    code, out, _ = run_cmd(base + ["-iTCP", "-sTCP:LISTEN"])
    if code == 0:
        socks += parse_lsof(out, "tcp")
    # UDP bindings (no LISTEN state, but useful)
    code, out, _ = run_cmd(base + ["-iUDP"])
    if code == 0:
        socks += parse_lsof(out, "udp")
    # de-dupe + sort
    uniq, seen = [], set()
    for s in socks:
        k = (s["proto"], s["ip"], s["port"], s["pid"])
        if k not in seen:
            seen.add(k); uniq.append(s)
    uniq.sort(key=lambda s: (s["proto"], s["ip"], s["port"], str(s["pid"])))
    return uniq

def list_ports_cross(use_sudo=False):
    osname = platform.system().lower()
    # Try psutil first (works on Linux/Windows; flaky on macOS without root)
    try:
        import psutil
        conns = psutil.net_connections(kind="inet")
        rows = []
        for c in conns:
            if getattr(psutil, "CONN_LISTEN", "LISTEN") != c.status and c.type != 2:  # allow UDP too
                continue
            if not c.laddr:
                continue
            ip = c.laddr.ip or "0.0.0.0"; port = int(c.laddr.port)
            proto = "tcp"  # psutil doesn’t expose easily; fine for now
            rows.append({"ip": ip, "port": port, "pid": c.pid, "process": None, "user": None, "proto": proto, "family": "ipv6" if ":" in ip and ip.count(".")==0 else "ipv4"})
        if rows:
            # de-dupe + sort
            uniq, seen = [], set()
            for s in rows:
                k = (s["proto"], s["ip"], s["port"], s["pid"])
                if k not in seen:
                    seen.add(k); uniq.append(s)
            uniq.sort(key=lambda s: (s["proto"], s["ip"], s["port"], str(s["pid"])))
            return uniq
    except Exception:
        pass

    # Fallbacks
    if osname == "darwin":
        return list_ports_macos(use_sudo=use_sudo)

    if osname == "linux":
        # Prefer ss; no sudo needed for basic info
        if shutil.which("ss"):
            code, out, _ = run_cmd((["sudo"] if use_sudo else []) + ["ss", "-ltnup"])
            if code == 0:
                rows = []
                for line in out.splitlines():
                    if "LISTEN" not in line and "UNCONN" not in line:  # tcp listen / udp unconnected
                        continue
                    parts = line.split()
                    addr = next((p for p in parts if ":" in p and not p.endswith(":*")), None)
                    if not addr or ":" not in addr: continue
                    ip, port_s = addr.rsplit(":", 1)
                    try: port = int(port_s)
                    except: continue
                    rows.append({"ip": ip, "port": port, "pid": None, "process": None, "user": None, "proto": "tcp" if "LISTEN" in line else "udp",
                                 "family": "ipv6" if ":" in ip and ip.count(".")==0 else "ipv4"})
                if rows: return rows
        # fallback to netstat similarly (omitted here for brevity)
        return []

    if osname == "windows":
        code, out, _ = run_cmd(["netstat", "-ano"])
        if code != 0: return []
        rows = []
        for line in out.splitlines():
            ln = line.strip()
            if not ln or ln.startswith("Proto"): continue
            if "LISTENING" in ln or "UDP" in ln:
                parts = ln.split()
                if len(parts) < 4: continue
                proto = parts[0].lower()
                local = parts[1]
                pid = parts[-1]
                if ":" not in local: continue
                ip, port_s = local.rsplit(":", 1)
                try: port = int(port_s)
                except: continue
                rows.append({"ip": ip, "port": port, "pid": pid, "process": None, "user": None,
                            "proto": proto, "family": "ipv6" if ":" in ip and ip.count(".")==0 else "ipv4"})
        return rows

    return []


def main():
    ap = argparse.ArgumentParser(description="Port grabber with macOS-friendly fallback")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--sudo", action="store_true", help="Use sudo for fallbacks (macOS/Linux)")
    args = ap.parse_args()

    rows = list_ports_cross(use_sudo=args.sudo)

    if not rows:
        print("No listening sockets found (or insufficient permissions). Try --sudo or start a test server: `python -m http.server 8000`")
        return

    if args.json:
        print(json.dumps(rows, indent=2))
        return

    print(f"{'ADDR':<24} {'PID':<7} {'PROC':<18} {'USER':<12} {'PROTO':<5} FAMILY")
    for s in rows:
        addr = f"{s['ip']}:{s['port']}"
        print(f"{addr:<24} {str(s['pid'] or '-'): <7} {str(s['process'] or '-'): <18} {str(s['user'] or '-'): <12} {s['proto']:<5} {s.get('family','-')}")

if __name__ == "__main__":
    main()
