#!/usr/bin/env python3


from __future__ import annotations
import argparse
import asyncio
import socket
import struct
import select
import selectors
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional
import time
import threading
import platform
import signal
import json

from chat_gpt.netops_toolkit import ROOT_REQUIRED_FEATURES, ICMP_ECHO_REQUEST

try:
    import psutil
except Exception:
    psutil = None

try:
    import paramiko
except Exception:
    paramiko = None

try:
    from pyroute2 import IPRoute, NetlinkError
except Exception:
    IPRoute = None
    NetlinkError = None

try:
    import netifaces
except Exception:
    netifaces = None

try:
    import scapy.all as scapy_all
except Exception:
    scapy_all = None


ROOT_REQUIRED_FEATURES = ("sniff", "rawping", "pyroute", "change-route", "arp-scan")

def is_root() -> bool:
    if os.name == "nt":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0 if 'ctypes' in globals() else False
    return os.getuid() == 0

def require_root_or_exit(feature: str):
    if not is_root():
        print(f"[ERROR] Feature '{feature}' requires root privileges.")
        sys.exit(1)

def nice_print(title: str, data: str = ""):
    print(f"\n=== {title} ===")
    if data:
        print(data)
    print()

def show_interfaces():
    nice_print("Interfaces & Addresses")
    if netifaces is None:
        print("netifaces not installed - falling back to socket-based listening.")
        if Path("/sys/class/net").exists():
            ifnames = sorted(os.listdir("/sys/class/net"))
            for ifn in ifnames:
                try:
                    addrs = socket.if_nameindex()
                except Exception:
                    pass
            print("Detected interfaces (limited):", ", ".join(ifnames))
        else:
            print("Cannot enumerate interfaces on this platform without netifaces.")
        return

    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        print(f"- {iface}")
        for fam, entries in addrs.items():
            fam_name = {netifaces.AF_INET: "IPv4", netifaces.AF_INET6: "IPv6", netifaces.AF_LINK: "MAC"}.get(fam, fam)
            for e in entries:
                print(f"  {fam_name}: {e}")
    print()

async def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    try:
        loop = asyncio.get_event_loop()
        fut = loop.create_connections(lambda: asyncio.Protocol(), host, port)
        conn = await asyncio.wait_for(fut, timeout=timeout)
        conn[0].close()
        return port, True
    except Exception:
        return port, False

async def async_port_scan(host: str, ports: List[int], concurrency: int = 200, timeout: float = 1.0):
    nice_print("Async port scan", f"Host: {host}\nPorts: {ports[:10]}{' ...' if len(ports) > 10 else ''}")
    sem = asyncio.Semaphore(concurrency)

    async def _scan(p):
        async with sem:
            return await scan_port(host, p, timeout=timeout)

    tasks = [asyncio.create_task(_scan(p)) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p, ok in results if ok]
    print("OPen ports:", open_ports)

ICMP_ECHO_REQUEST = 8

def checksum(source: bytes) -> int:
    if len(source) % 2:
        source += b'\x00'
    s = 0
    for i in range(0, len(source), 2):
        w = source[i] << 8 | source[i+1]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

def raw_ping(host: str, timeout: float = 1.0, seq: int = 1) -> bool:
    require_root_or_exit("rawping")
    try:
        dest = socket.gethostbyname(host)
    except Exception as e:
        print(f"resolve error: {e}")
        return False

    my_id = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, my_id, seq)
    data = struct.pack("d", time.time())
    chk = checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(chk), my_id)
    packet = header + data

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
        s.settimeout(timeout)
        s.sendto(packet, (dest, 1))
        try:
            rec, addr = s.recvfrom(1024)
            ip_header_len = (rec[0] & 0x0F) * 4
            icmp_header = rec[ip_header_len:ip_header_len+8]
            r_type, r_code, r_checksum, r_id, r_seq = struct.unpack("bbHHh", icmp_header)
            if r_type == 0 and r_id == my_id:
                return True
        except socket.timeout:
            return False
    return False

def selector_echo_server(host: str = "0.0.0.0", port: int = 9999, timeout: Optional[float] = None):
    nice_print("Selector-based echo server", f"{host}:{port} (CTRL+C to stop)")
    sel = selectors.DefaultSelector()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((host, port))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:
            events = sel.select(timeout)
            if not events:
                continue
            for key, mask in events:
                if key.data is None:
                    conn, addr = key.fileobj.accept()
                    conn.setblocking(False)
                    sel.register(conn, selectors.EVENT_READ, data=addr)
                    print(f"Accepted {addr}")
                else:
                    conn = key.fileobj
                    addr = key.data
                    data = conn.recv(4096)
                    if data:
                        conn.sendall(data) # <- echo
                    else:
                        sel.unregister(conn)
                        conn.close()
                        print(f"Closed {addr}")
    except KeyboardInterrupt:
        print("Server interrupted, shutting down.")
    finally:
        sel.close()
        lsock.close()

def ensure_scapy():
    if scapy_all is None:
        print("[ERROR] Scapy isn't available (scapy not installed). Install via 'pip install scapy' ")
        sys.exit(1)

def arp_scan(network: str = "192.168.0.0/24", timeout: int = 2):
    ensure_scapy()
    require_root_or_exit("arp-scan")
    nice_print("ARP scan", f"Network: {network}")
    ans, unans = scapy_all.arping(network, timeout=timeout, verbose=False)
    for snd, rcv in ans:
        print(f"{rcv.psrc} - {rcv.hwsrc}")

def sniff_packets(filter_expr: Optional[str] = None, count: int = 0, iface: Optional[str] = None):
    ensure_scapy()
    require_root_or_exit("sniff")
    nice_print("Packet Sniffing", f"filter='{filter_expr}' iface={iface} count={count or 'infinite'}")
    def _pkt(pkt):
        print(pkt.summary())
    scapy_all.sniff(filter=filter_expr, prn=_pkt, count=count or 0, iface=iface)

def ssh_execute(host: str, username: str, password: Optional[str] = None, key_file: Optional[str] = None, cmd: str = "uname -a", port: int = 22, timeout: int = 10):
    if paramiko is None:
        print("[ERROR] paramiko is not installed. Install via 'pip install paramiko'.")
        return None, None, None

    nice_print("SSH execute", f"{username}@{host}:{port} -> {cmd}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_file:
            pkey = paramiko.RSAkey.from_private_key_file(key_file)
            client.connect(hostname=host, port=port, username=username, pkey=pkey, timeout=timeout)
        else:
            client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        exit_status = stdout.channel.recv_exit_status()
        print("Exit:", exit_status)
        print("STDOUT:\n", out)
        print("STDERR:\n", err)
        return out, err, exit_status
    except Exception as e:
        print("SSH error:", e)
        return None, None, None
    finally:
        try:
            client.close()
        except Exception:
            pass

def show_routes():
    if IPRoute is None:
        print("[ERROR] pyroute2 is not installed, Install via 'pip install pyroute2'.")
        return
    require_root_or_exit("pyroute")
    ipr = IPRoute()
    routes = ipr.get_routes()
    nice_print("Kernel Routes")
    for r in routes:
        attrs = dict(r.get('attrs', []))
        dst = attrs.get('RTA_DST', 'default')
        gateway = attrs.get('RTA_GATEWAY', None)
        oif = r .get('oif', None)
        print(f"dst={dst} via={gateway} oif={oif}")
    ipr.close()

def add_route(dst: str, gateway: str, oif: Optional[int] = None):
    if IPRoute is None:
        print("[ERROR] pyroute2 is not installed, Install via 'pip install pyroute2'.")
        return
    require_root_or_exit("change-route")
    ipr = IPRoute()
    try:
        ipr.route('add', dst=dst if dst != "default" else None, gateway=gateway, oif=oif)
        print("Route added")
    except NetlinkError as e:
        print("Failed to add route:", e)
    finally:
        ipr.close()

def show_system_stats():
    nice_print("System Stats")
    if psutil is None:
        print("psutil not installed. Run 'pip install psutil'")
        return
    print("CPU:", psutil.cpu_percent(interval=1), "%")
    print("Per-cpu:", psutil.cpu_percent(interval=0.5, percpu=True))
    mem = psutil.virtual_memory()
    print(f"Memory: {mem.total/1024**2:.1f}MB available ({mem.percent}%)")
    print("Disk Usage /:", psutil.disk_usage("/").percent, "%")
    print("Network IO:", psutil.net_io_counters())

def run_shell(cmd: str, capture: bool = True, check: bool = False, shell: bool = False):
    nice_print("Shell Command", cmd)
    try:
        if capture:
            out = subprocess.run(cmd if isinstance(cmd, list) else cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, shell=shell)
            print(out.stdout.decode(errors="ignore"))
            if out.stderr:
                print("STDERR:", out.stderr.decode(errors="ignore"))
            return out.returncode, out.stdout.decode(errors="ignore"), out.stderr.decode(errors="ignore")
        else:
            rc = subprocess.call(cmd if isinstance(cmd, list) else cmd.split())
            return rc, None, None
    except Exception as e:
        print("Subprocess error:", e)
        return -1, None, str(e)

async def discover_and_ssh_workflow(base_network: str, ssh_user: str, ssh_pass: Optional[str], cmd: str):
    ensure_scapy()
    if paramiko is None:
        print("[ERROR] paramiko required for this workflow.")
        return
    require_root_or_exit("arp-scan")
    nice_print("Discover & SSH Workflow", f"Network: {base_network} | cmd: {cmd}")
    ans, _ = scapy_all.arping(base_network, timeout=2, verbose=False)
    hosts = [rcv.psrc for snd, rcv in ans]
    print("Discovered hosts:", hosts)
    for host in hosts:
        print(f"\n-- Trying {host}")
        try:
            out, err, code = ssh_execute(host, ssh_user, password=ssh_pass, cmd=cmd)
            print("Result:", code)
        except Exception as e:
            print("Error:", e)

async def asyncio_echo_server(host: str = "0.0.0.0", port: int = 9998):
    server = await asyncio.start_server(lambda r, w: echo_handler(r, w), host, port)
    addr = server.sockets[0].getsockname()
    nice_print("AsyncIO Echo Server", f"Serving on {addr}")
    async with server:
        await server.serve_forever()

async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    print(f"Client connected {peer}")
    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        print("Echo handler error:", e)
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"Connection closed {peer}")

async def asyncio_echo_client(host: str, port: int, message: str):
    reader, writer = await asyncio.open_connection(host, port)
    print(f"Connected to {host}:{port} -> sending {message!r}")
    writer.write(message.encode())
    await writer.drain()
    data = await reader.read(4096)
    print("Received:", data.decode())
    writer.close()
    await writer.wait_closed()


def list_connections():
    nice_print("active TCP connections")
    if psutil is None:
        print("psutil not available - falling back to socket listening")
        return
    for c in psutil.net_connections(kind='tcp'):
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        print(f"pid={c.pid} {laddr} -> {raddr} status={c.status}")

def parse_ports_list(portspec: str) -> List[int]:
    ports = set()
    for part in portspec.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="Netops Toolkit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("interfaces", help="netifaces")

    scan = sub.add_parser("portscan", help="async port scan")
    scan.add_argument("host", help="host to scan")
    scan.add_argument("--ports", default="1-1024", help="Ports")
    scan.add_argument("--concurrency", type=int, default=200)

    ping = sub.add_parser("ping", help="ICMP ping")
    ping.add_argument("host", help="host to ping")

    selserv = sub.add_parser("sel-echo", help="selector-based server")
    selserv.add_argument("--host", default="0.0.0.0")
    selserv.add_argument("--port", type=int, default=9999)

    sc = sub.add_parser("scapy-arp", help="ARP scan")
    sc.add_argument("network", help="Network")

    sniff = sub.add_parser("sniff", help="sniff packets")
    sniff.add_argument("--filter", default=None)
    sniff.add_argument("--count", type=int, default=0)
    sniff.add_argument("--iface", default=None)

    ssh = sub.add_parser("ssh", help="SSH paramiko")
    ssh.add_argument("host")
    ssh.add_argument("--user", required=True)
    ssh.add_argument("--password", default=None)
    ssh.add_argument("--key", default=None)
    ssh.add_argument("--subcommand", default="uname -a")

    routes = sub.add_parser("routes", help="Show kernel routes")
    routes2 = sub.add_parser("add-route", help="add kernel route")
    routes2.add_argument("dst", help="'default' or CIDR")
    routes2.add_argument("gateway", help="Gateway IP")
    routes2.add_argument("--oif", type=int, default=None)

    stats = sub.add_parser("stats", help="Show system stats")

    shell = sub.add_parser("shell", help="Run a shell command")
    shell.add_argument("subcmd", help="command to run")

    discover = sub.add_parser("discover-ssh", help="ARP discover and SSH")
    discover.add_argument("network", help="network for discovery")
    discover.add_argument("--user", required=True)
    discover.add_argument("--password", default=None)
    discover.add_argument("--command", default="uname -a")

    selscan = sub.add_parser("list-conns", help="List active connections")

    aios = sub.add_parser("aio-echo-client", help="asyncio echo client")
    aios.add_argument("--host", default="0.0.0.0")
    aios.add_argument("--port", type=int, default=9998)

    acli = sub.add_parser("aio-echo-client", help="asyncio client")
    acli.add_argument("host")
    acli.add_argument("port", type=int)
    acli.add_argument("message")

    args = parser.parse_args()

    if args.cmd == "interfaces":
        show_interfaces()

    elif args.cmd == "portscan":
        ports = parse_ports_list(args.ports)
        try:
            asyncio.run(async_port_scan(args.host, ports, concurrency=args.concurrency))
        except KeyboardInterrupt:
            print("scan interrupted")

    elif args.cmd == "ping":
        ok = raw_ping(args.host)
        print(f"Ping {args.host}: {'alive' if ok else 'no response'}")

    elif args.cmd == "sel-echo":
        selector_echo_server(host=args.host, port=args.port)

    elif args.cmd == "scapy-arp":
        arp_scan(args.network)

    elif args.cmd == "sniff":
        sniff_packets(filter_expr=args.filter, count=args.count, iface=args.iface)

    elif args.cmd == "ssh":
        ssh_execute(args.host, username=args.user, password=args.password, key_file=args.key, cmd=args.subcommand)

    elif args.cmd == "routes":
        show_routes()

    elif args.cmd == "add-route":
        add_route(args.dst, args.gateway, oif=args.oif)

    elif args.cmd == "stats":
        show_system_stats()

    elif args.cmd == "shell":
        run_shell(args.subcmd, capture=True)

    elif args.cmd == "discover-ssh":
        try:
            asyncio.run(discover_and_ssh_workflow(args.network, args.user, args.password, args.command))
        except KeyboardInterrupt:
            pass

    elif args.cmd == "list-conns":
        list_connections()

    elif args.cmd == "aio-echo-server":
        try:
            asyncio.run(asyncio_echo_server(host=args.host, port=args.port))
        except KeyboardInterrupt:
            pass

    elif args.cmd == "aio-echo-client":
        try:
            asyncio.run(asyncio_echo_client(args.host, args.port, args.message))
        except KeyboardInterrupt:
            pass

    else:
        parser.print_help()

if __name__ == "__main__":
    main()




















