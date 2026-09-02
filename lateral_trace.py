#!/usr/bin/env python3
"""
Lateral Trace — Lateral Movement Path Finder & Network Pivot Mapper
Maps potential lateral movement paths from current host: open ports, trust relationships, reachable hosts.
Author: Omar Khalid (amooryx) | github.com/amooryx/lateral-trace
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

PIVOT_PORTS = [22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 5986, 6379, 27017]

def run(cmd: str) -> str:
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        return ""

def get_network_interfaces() -> list[dict]:
    """Get local network interfaces and their subnets."""
    ifaces = []
    if platform.system() == "Windows":
        out = run("ipconfig /all")
        # Parse Windows ipconfig
        for block in out.split("\n\n"):
            if "IPv4" in block or "IPv6" in block:
                ip = ""
                for line in block.splitlines():
                    if "IPv4" in line:
                        ip = line.split(":")[-1].strip().rstrip("(Preferred)")
                if ip and not ip.startswith("127."):
                    ifaces.append({"ip": ip, "interface": "unknown"})
    else:
        out = run("ip addr 2>/dev/null || ifconfig -a")
        for line in out.splitlines():
            if "inet " in line and "127.0.0" not in line:
                parts = line.strip().split()
                idx = parts.index("inet") + 1 if "inet" in parts else -1
                if idx > 0 and "/" in parts[idx]:
                    ip = parts[idx].split("/")[0]
                    ifaces.append({"ip": ip, "cidr": parts[idx]})
    return ifaces

def get_arp_table() -> list[dict]:
    """Get ARP cache — recently seen hosts on the LAN."""
    hosts = []
    if platform.system() == "Windows":
        out = run("arp -a")
    else:
        out = run("arp -n 2>/dev/null || ip neigh 2>/dev/null")
    for line in out.splitlines():
        parts = line.split()
        for part in parts:
            try:
                socket.inet_aton(part)
                if not part.startswith(("127.", "0.", "255.")):
                    hosts.append({"ip": part, "source": "arp"})
                    break
            except Exception:
                pass
    return hosts

def check_host_ports(ip: str, ports: list[int], timeout: float = 1.5) -> dict:
    open_ports = []
    for port in ports:
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            open_ports.append(port)
        except Exception:
            pass
    return {"ip": ip, "open_ports": open_ports}

def get_ssh_known_hosts() -> list[str]:
    hosts = []
    for f in ["~/.ssh/known_hosts", "~/.ssh/known_hosts2"]:
        p = os.path.expanduser(f)
        if os.path.exists(p):
            with open(p) as file:
                for line in file:
                    if line.strip() and not line.startswith("#"):
                        host = line.split()[0].split(",")[0].lstrip("[")
                        if host and not host.startswith("@"):
                            hosts.append(host)
    return list(set(hosts))

def get_rdp_history_windows() -> list[str]:
    """Read RDP MRU (most recently used hosts) from registry."""
    hosts = []
    if platform.system() == "Windows":
        out = run(r'reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" 2>nul')
        for line in out.splitlines():
            if "MRU" in line and "REG_SZ" in line:
                host = line.split("REG_SZ")[-1].strip()
                if host:
                    hosts.append(host)
    return hosts

def main():
    parser = argparse.ArgumentParser(
        description="Lateral Trace — Lateral Movement Path Finder (Authorized use only)",
    )
    parser.add_argument("--arp",      action="store_true", help="Enumerate ARP table")
    parser.add_argument("--ifaces",   action="store_true", help="List network interfaces")
    parser.add_argument("--ssh",      action="store_true", help="Check SSH known_hosts")
    parser.add_argument("--rdp",      action="store_true", help="Check RDP MRU (Windows)")
    parser.add_argument("--scan",     action="store_true", help="Port scan discovered hosts")
    parser.add_argument("--threads",  type=int, default=50)
    parser.add_argument("--timeout",  type=float, default=1.5)
    parser.add_argument("--all", "-a", action="store_true")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    if not (args.arp or args.ifaces or args.ssh or args.rdp or args.scan or args.all):
        args.all = True

    results  = {}
    all_ips  = []

    if args.ifaces or args.all:
        ifaces = get_network_interfaces()
        print(f"[+] Network interfaces: {len(ifaces)}")
        for i in ifaces:
            print(f"    {i}")
        results["interfaces"] = ifaces

    if args.arp or args.all:
        arp = get_arp_table()
        print(f"[+] ARP cache: {len(arp)} hosts")
        for h in arp:
            print(f"    {h['ip']}")
        results["arp"] = arp
        all_ips.extend([h["ip"] for h in arp])

    if args.ssh or args.all:
        ssh_hosts = get_ssh_known_hosts()
        print(f"[+] SSH known_hosts: {len(ssh_hosts)}")
        for h in ssh_hosts[:10]:
            print(f"    {h}")
        results["ssh_known_hosts"] = ssh_hosts
        all_ips.extend(ssh_hosts)

    if (args.rdp or args.all) and platform.system() == "Windows":
        rdp_hosts = get_rdp_history_windows()
        print(f"[+] RDP MRU history: {len(rdp_hosts)}")
        for h in rdp_hosts:
            print(f"    {h}")
        results["rdp_history"] = rdp_hosts
        all_ips.extend(rdp_hosts)

    if (args.scan or args.all) and all_ips:
        targets = list(set(all_ips))
        print(f"[*] Port scanning {len(targets)} discovered hosts ...")
        scan_results = []
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            futures = {exe.submit(check_host_ports, ip, PIVOT_PORTS, args.timeout): ip
                       for ip in targets}
            for fut in futures:
                r = fut.result()
                if r["open_ports"]:
                    print(f"  [+] {r['ip']}: {r['open_ports']}")
                    scan_results.append(r)
        results["scan"] = scan_results

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
