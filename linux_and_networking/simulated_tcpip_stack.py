#!/usr/bin/env python3
"""
simulated_tcpip_stack.py

Educational simulation of the TCP/IP stack across layers:
- Physical: simulated unreliable medium (delay/drop)
- Data Link: Ethernet frames, simple MAC addresses, ARP
- Network: IPv4-like packets and routing table
- Transport: UDP and a simulated TCP (states, seq/ack, retransmit timers)
- Application: simulated HTTP-like request/response and a real localhost echo server comparison

Author: ChatGPT (for study)
Run: python3 simulated_tcpip_stack.py
"""

import threading
import time
import random
import queue
import socket
import struct
from enum import Enum, auto
from typing import Dict, Optional, Tuple, List

# ---------------------------
# Utilities & Logging
# ---------------------------
LOG_LOCK = threading.Lock()


def log(node: str, msg: str):
    with LOG_LOCK:
        ts = f"{time.time():.3f}"
        print(f"[{ts}] [{node}] {msg}")


def gen_mac():
    """Generate a random but nicely formatted MAC (not real-world unique)."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0x00, 0x7f) for _ in range(5))


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(i: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", i))


# ---------------------------
# Physical Layer
# ---------------------------
class PhysicalMedium:
    """
    Simulates a shared medium where frames are queued between endpoints.
    You can configure delay and drop rate to see how higher layers react.
    """
    def __init__(self, name="NET", drop_rate=0.0, avg_delay=0.01, jitter=0.02):
        self.name = name
        self.links = {}  # mac -> queue.Queue
        self.drop_rate = drop_rate
        self.avg_delay = avg_delay
        self.jitter = jitter

    def attach(self, mac: str):
        q = queue.Queue()
        self.links[mac] = q
        log(self.name, f"Attached MAC {mac}")
        return q

    def detach(self, mac: str):
        if mac in self.links:
            del self.links[mac]

    def send(self, src_mac: str, dst_mac: str, raw_frame: bytes):
        """Place frame on dst_mac queue (or broadcast to all)."""
        # simulate unreliable medium
        if random.random() < self.drop_rate:
            log(self.name, f"DROP frame from {src_mac} to {dst_mac} (simulated)")
            return

        delay = max(0.0, random.gauss(self.avg_delay, self.jitter))
        def deliver():
            time.sleep(delay)
            if dst_mac == "ff:ff:ff:ff:ff:ff":
                # broadcast to everyone except sender
                for mac, q in list(self.links.items()):
                    if mac != src_mac:
                        q.put((src_mac, raw_frame))
            else:
                q = self.links.get(dst_mac)
                if q:
                    q.put((src_mac, raw_frame))
                else:
                    log(self.name, f"No link for {dst_mac}; frame lost")

        threading.Thread(target=deliver, daemon=True).start()


# ---------------------------
# Data Link Layer (Ethernet + ARP)
# ---------------------------
ETHERTYPE_IP = 0x0800
ETHERTYPE_ARP = 0x0806


class EthernetFrame:
    def __init__(self, dst_mac: str, src_mac: str, ethertype: int, payload: bytes):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.ethertype = ethertype
        self.payload = payload

    def to_bytes(self) -> bytes:
        # Very simple serialization: mac string lengths + ethertype + payload
        data = f"{self.dst_mac}|{self.src_mac}|{self.ethertype}|".encode("utf-8") + self.payload
        return data

    @staticmethod # <-This method does not need self, so you can call it on the class itself:
    def from_bytes(b: bytes):
        header, payload = b.split(b"|", 3)[:3], b.split(b"|", 3)[3]
        # header parsing (hacky but fine for simulation)
        parts = b.decode("utf-8", errors="ignore").split("|", 3)
        dst, src, eth = parts[0], parts[1], int(parts[2])
        # payload are the bytes after the third '|'
        payload = parts[3].encode("utf-8", errors="ignore")
        return EthernetFrame(dst, src, eth, payload)


class ARP:
    """Simple ARP table mapping IPv4 (string) to MAC (string)."""
    def __init__(self):
        self.table: Dict[str, str] = {}

    def request(self, src_mac: str, src_ip: str, target_ip: str):
        # return a "packet" for the simulation
        return f"ARP_REQ|{src_mac}|{src_ip}|{target_ip}".encode("utf-8")

    def reply(self, src_mac: str, src_ip: str, target_mac: str, target_ip: str):
        return f"ARP_REP|{src_mac}|{src_ip}|{target_mac}|{target_ip}".encode("utf-8")

    @staticmethod
    def parse(payload: bytes):
        text = payload.decode("utf-8")
        parts = text.split("|")
        if parts[0] == "ARP_REQ":
            return ("REQ", parts[1], parts[2], parts[3])  # src_mac, src_ip, target_ip
        else:
            # ARP_REP
            return ("REP", parts[1], parts[2], parts[3], parts[4])  # src_mac, src_ip, target_mac, target_ip


# ---------------------------
# Network Layer (IP)
# ---------------------------
class IPPacket:
    """Very simplified IPv4 packet representation."""
    def __init__(self, src_ip: str, dst_ip: str, proto: int, payload: bytes, ttl: int = 64):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto  # 6=tcp,17=udp
        self.payload = payload
        self.ttl = ttl
        # not implementing header checksum for brevity

    def to_bytes(self) -> bytes:
        header = f"{self.src_ip}|{self.dst_ip}|{self.proto}|{self.ttl}|".encode("utf-8")
        return header + self.payload

    @staticmethod
    def from_bytes(b: bytes):
        # parse with our simple format
        s = b.decode("utf-8", errors="ignore")
        parts = s.split("|", 4)
        src, dst, proto_str, ttl_str = parts[0], parts[1], parts[2], parts[3]
        payload = parts[4].encode("utf-8", errors="ignore")
        return IPPacket(src, dst, int(proto_str), payload, int(ttl_str))


# ---------------------------
# Transport Layer (UDP & Simulated TCP)
# ---------------------------
UDP_PROTO = 17
TCP_PROTO = 6

class UDPSegment:
    def __init__(self, src_port: int, dst_port: int, data: bytes):
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = data

    def to_bytes(self) -> bytes:
        header = f"UDP|{self.src_port}|{self.dst_port}|".encode("utf-8")
        return header + self.data

    @staticmethod
    def from_bytes(b: bytes):
        text = b.decode("utf-8", errors="ignore")
        parts = text.split("|", 3)
        return UDPSegment(int(parts[1]), int(parts[2]), parts[3].encode("utf-8", errors="ignore"))


class TCPState(Enum):
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECV = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    TIME_WAIT = auto()


class TCPSegment:
    """
    Simple TCP segment representation:
    - seq, ack, flags (SYN/ACK/FIN), window (not dynamically used here), payload.
    """
    def __init__(self, src_port: int, dst_port: int, seq: int = 0, ack: int = 0,
                 syn=False, ack_flag=False, fin=False, window=1024, payload: bytes = b""):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.syn = syn
        self.ack_flag = ack_flag
        self.fin = fin
        self.window = window
        self.payload = payload

    def to_bytes(self) -> bytes:
        flags = f"{int(self.syn)}{int(self.ack_flag)}{int(self.fin)}"
        header = f"TCP|{self.src_port}|{self.dst_port}|{self.seq}|{self.ack}|{flags}|{self.window}|".encode("utf-8")
        return header + self.payload

    @staticmethod
    def from_bytes(b: bytes):
        text = b.decode("utf-8", errors="ignore")
        parts = text.split("|", 8)
        src_port = int(parts[1]); dst_port = int(parts[2])
        seq = int(parts[3]); ack = int(parts[4])
        flags = parts[5]
        syn = flags[0] == "1"
        ack_flag = flags[1] == "1"
        fin = flags[2] == "1"
        window = int(parts[6])
        payload = parts[7].encode("utf-8", errors="ignore")
        return TCPSegment(src_port, dst_port, seq, ack, syn, ack_flag, fin, window, payload)


# ---------------------------
# Host & Interface
# ---------------------------
class NetInterface:
    """Represents a host interface with an IP and MAC and a physical queue."""
    def __init__(self, name: str, mac: str, ip: str, medium: PhysicalMedium):
        self.name = name
        self.mac = mac
        self.ip = ip
        self.medium = medium
        self.queue = medium.attach(mac)
        self.arp = ARP()
        self.alive = True
        self.handlers = {
            ETHERTYPE_ARP: self._handle_arp,
            ETHERTYPE_IP: self._handle_ip
        }
        # callbacks set by owner host
        self.ip_in_callback = None  # signature: (ip_packet, src_mac)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log(self.name, f"Interface created MAC={mac} IP={ip}")

    def send_ether(self, dst_mac: str, ethertype: int, payload: bytes):
        frame = EthernetFrame(dst_mac, self.mac, ethertype, payload)
        self.medium.send(self.mac, dst_mac, frame.to_bytes())
        log(self.name, f"send_ether -> dst={dst_mac} eth={hex(ethertype)} len={len(payload)}")

    def send_ip(self, dst_ip: str, proto: int, payload: bytes, ttl=64):
        # need to resolve dst_ip -> dst_mac via ARP (very simplified)
        dst_mac = self.arp.table.get(dst_ip)
        if not dst_mac:
            # send ARP request (broadcast)
            self.send_ether("ff:ff:ff:ff:ff:ff", ETHERTYPE_ARP, self.arp.request(self.mac, self.ip, dst_ip))
            # in a real stack you'd wait for reply; here we assume asynchronous arrival
            # we'll still send an IP packet later after ARP resolution by a simple retry mechanism
            # store the packet in a "pending" queue - for simplicity we retry a few times
            attempts = 0
            while attempts < 5:
                time.sleep(0.05)
                dst_mac = self.arp.table.get(dst_ip)
                if dst_mac:
                    break
                attempts += 1
            if not dst_mac:
                log(self.name, f"ARP resolution failed for {dst_ip}; dropping IP packet")
                return
        ip = IPPacket(self.ip, dst_ip, proto, payload, ttl)
        self.send_ether(dst_mac, ETHERTYPE_IP, ip.to_bytes())

    def _handle_arp(self, payload: bytes, src_mac: str):
        parsed = ARP.parse(payload)
        if parsed[0] == "REQ":
            _, req_src_mac, req_src_ip, target_ip = parsed
            if target_ip == self.ip:
                # send reply with our mac
                rep = self.arp.reply(self.mac, self.ip, req_src_mac, req_src_ip)
                self.send_ether(req_src_mac, ETHERTYPE_ARP, rep)
                log(self.name, f"Replied ARP to {req_src_ip}")
        else:
            # ARP reply
            _, r_src_mac, r_src_ip, target_mac, target_ip = parsed
            # add to ARP table
            self.arp.table[target_ip] = target_mac
            log(self.name, f"ARP table updated: {target_ip} -> {target_mac}")

    def _handle_ip(self, payload: bytes, src_mac: str):
        ip_pkt = IPPacket.from_bytes(payload)
        # deliver to owner
        if self.ip_in_callback:
            self.ip_in_callback(ip_pkt, src_mac)

    def _run(self):
        while self.alive:
            try:
                src_mac, raw = self.queue.get(timeout=0.2)
                # naive parsing back to EthernetFrame
                try:
                    # split using the first three '|' characters - compatible with to_bytes
                    raw_str = raw.decode("utf-8", errors="ignore")
                    parts = raw_str.split("|", 3)
                    dst, src, eth = parts[0], parts[1], int(parts[2])
                    payload_part = parts[3].encode("utf-8", errors="ignore")
                    handler = self.handlers.get(eth)
                    if handler:
                        handler(payload_part, src_mac)
                    else:
                        log(self.name, f"Unknown ethertype {eth} received")
                except Exception as e:
                    log(self.name, f"Error parsing frame: {e}")
            except queue.Empty:
                continue

    def shutdown(self):
        self.alive = False
        self.medium.detach(self.mac)


# ---------------------------
# Simple Router (for simulation)
# ---------------------------
class SimpleRouter:
    """A router with static routing table for the simulation."""
    def __init__(self, name: str, medium: PhysicalMedium):
        self.name = name
        self.interfaces: Dict[str, NetInterface] = {}  # ip -> interface
        self.rt_table: List[Tuple[int, str, NetInterface]] = []  # (network_int_masked, maskbits, interface)
        self.medium = medium

    def add_interface(self, ip: str, mac: str):
        iface = NetInterface(self.name + "-" + ip, mac, ip, self.medium)
        iface.ip_in_callback = self._recv_ip
        self.interfaces[ip] = iface
        return iface

    def add_route(self, network: str, mask_bits: int, interface_ip: str):
        net_int = ip_to_int(network) & (~((1 << (32 - mask_bits)) - 1))
        iface = self.interfaces[interface_ip]
        self.rt_table.append((net_int, mask_bits, iface))
        log(self.name, f"Added route {network}/{mask_bits} -> {iface.ip}")

    def _recv_ip(self, ip_pkt: IPPacket, src_mac: str):
        # decrement TTL and route
        log(self.name, f"Router received IP {ip_pkt.src_ip} -> {ip_pkt.dst_ip} proto={ip_pkt.proto}")
        ip_pkt.ttl -= 1
        if ip_pkt.ttl <= 0:
            log(self.name, f"Dropped packet: TTL expired")
            return
        dst_int = ip_to_int(ip_pkt.dst_ip)
        # longest prefix match
        best = None
        best_len = -1
        for net_int, mask_bits, iface in self.rt_table:
            mask = (~((1 << (32 - mask_bits)) - 1)) & 0xffffffff
            if (dst_int & mask) == net_int and mask_bits > best_len:
                best = iface
                best_len = mask_bits
        if best:
            # forward: ensure ARP resolution etc.
            log(self.name, f"Forwarding packet to interface {best.ip}")
            best.send_ip(ip_pkt.dst_ip, ip_pkt.proto, ip_pkt.payload, ip_pkt.ttl)
        else:
            log(self.name, f"No route found for {ip_pkt.dst_ip}")


# ---------------------------
# TCP Endpoint (state machine)
# ---------------------------
class TCPConnection:
    """
    Very simplified TCP connection handler that models:
    - 3-way handshake (SYN,SYN-ACK,ACK)
    - sequence numbers and ACKing
    - sending data segments, acknowledging
    - FIN close (graceful)
    - basic retransmit: if no ACK within timeout, retransmit (limited attempts)
    This is a model for study, not a full TCP implementation.
    """
    RETRANSMIT_TIMEOUT = 0.5  # seconds
    MAX_RETRANSMIT = 5

    def __init__(self, owner_name: str, iface: NetInterface, src_port: int, dst_ip: str, dst_port: int, passive=False):
        self.owner_name = owner_name
        self.iface = iface
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.state = TCPState.CLOSED
        self.send_seq = random.randint(1, 1000)
        self.recv_seq = 0
        self.unacked = {}  # seq -> (segment, send_time, attempts)
        self.app_recv_buffer = b""
        self.lock = threading.Lock()
        self.timers = {}
        self.alive = True
        self.passive = passive
        # register inbound IP handler for TCP
        # Higher-level manager handles demultiplexing by port; we simulate it simply.
        # The interface will call provided callback; the host will dispatch to correct socket.

    def _send_segment(self, seg: TCPSegment):
        data = seg.to_bytes()
        self.iface.send_ip(self.dst_ip, TCP_PROTO, data)
        if seg.payload or seg.syn or seg.fin:
            # track for retransmit if necessary
            with self.lock:
                self.unacked[seg.seq] = (seg, time.time(), 0)
        log(self.owner_name, f"TCP SEND seg seq={seg.seq} ack={seg.ack} syn={seg.syn} ackf={seg.ack_flag} fin={seg.fin} len={len(seg.payload)}")

    def handle_incoming(self, seg: TCPSegment):
        """Process an incoming TCP segment (one connection's view)."""
        log(self.owner_name, f"TCP IN seg seq={seg.seq} ack={seg.ack} syn={seg.syn} ackf={seg.ack_flag} fin={seg.fin} len={len(seg.payload)}")
        with self.lock:
            if self.state == TCPState.CLOSED:
                if seg.syn and self.passive:
                    # Act as server: SYN -> SYN-ACK
                    self.recv_seq = seg.seq + 1
                    self.send_seq = random.randint(1000, 2000)
                    resp = TCPSegment(self.src_port, self.dst_port, seq=self.send_seq, ack=self.recv_seq, syn=True, ack_flag=True)
                    self._send_segment(resp)
                    self.state = TCPState.SYN_RECV
                    self.send_seq += 1  # account for SYN
                    log(self.owner_name, f"State -> SYN_RECV (sent SYN-ACK)")
            elif self.state == TCPState.SYN_SENT:
                if seg.syn and seg.ack_flag and seg.ack == self.send_seq:
                    # received SYN-ACK -> send ACK, state ESTABLISHED
                    self.recv_seq = seg.seq + 1
                    ack_seg = TCPSegment(self.src_port, self.dst_port, seq=self.send_seq, ack=self.recv_seq, ack_flag=True)
                    self._send_segment(ack_seg)
                    self.state = TCPState.ESTABLISHED
                    log(self.owner_name, f"State -> ESTABLISHED (active open)")
            elif self.state == TCPState.SYN_RECV:
                if seg.ack_flag and seg.ack == self.send_seq:
                    # client's ACK of our SYN-ACK
                    self.state = TCPState.ESTABLISHED
                    log(self.owner_name, f"State -> ESTABLISHED (passive open)")
            elif self.state == TCPState.ESTABLISHED:
                # handle data
                if seg.payload:
                    # accept in-order payload only for simplicity
                    self.app_recv_buffer += seg.payload
                    self.recv_seq = seg.seq + len(seg.payload)
                    # send ACK
                    ack_seg = TCPSegment(self.src_port, self.dst_port, seq=self.send_seq, ack=self.recv_seq, ack_flag=True)
                    self.iface.send_ip(self.dst_ip, TCP_PROTO, ack_seg.to_bytes())
                    log(self.owner_name, "ACK sent for received data")
                if seg.ack_flag:
                    # remove acked segments from unacked
                    to_del = []
                    for s, (segobj, t0, attempts) in self.unacked.items():
                        # simplistic: if seg.ack >= segobj.seq + len(payload) -> it's acked
                        payload_len = len(segobj.payload)
                        end_seq = segobj.seq + (1 if segobj.syn else 0) + payload_len + (1 if segobj.fin else 0)
                        if seg.ack >= end_seq:
                            to_del.append(s)
                    for s in to_del:
                        del self.unacked[s]
                if seg.fin:
                    # peer closing
                    self.recv_seq = seg.seq + 1
                    # send ACK
                    ack_seg = TCPSegment(self.src_port, self.dst_port, seq=self.send_seq, ack=self.recv_seq, ack_flag=True)
                    self.iface.send_ip(self.dst_ip, TCP_PROTO, ack_seg.to_bytes())
                    self.state = TCPState.CLOSE_WAIT
                    log(self.owner_name, "Received FIN; State -> CLOSE_WAIT")
            # other states truncated for brevity

    def active_open(self):
        """Client-side open: send SYN and wait (async) for ESTABLISHED."""
        if self.state != TCPState.CLOSED:
            raise Exception("Socket not closed")
        self.send_seq = random.randint(1, 1000)
        syn_seg = TCPSegment(self.src_port, self.dst_port, seq=self.send_seq, syn=True)
        self._send_segment(syn_seg)
        self.send_seq += 1
        self.state = TCPState.SYN_SENT
        log(self.owner_name, "Active open: SYN sent, State -> SYN_SENT")

    def send_data(self, data: bytes):
        """Chop data into segments (we will send as one seg here)"""
        if self.state != TCPState.ESTABLISHED:
            log(self.owner_name, "Cannot send: not established")
            return
        seg = TCPSegment(self.src_port, self.dst_port, seq=self.send_seq, ack=self.recv_seq, payload=data)
        self._send_segment(seg)
        self.send_seq += len(data)

    def poll_retransmit(self):
        """Should be called periodically to retransmit unacked segments."""
        now = time.time()
        with self.lock:
            for seq, (seg, t0, attempts) in list(self.unacked.items()):
                if now - t0 > self.RETRANSMIT_TIMEOUT:
                    if attempts >= self.MAX_RETRANSMIT:
                        log(self.owner_name, f"Segment seq={seq} retransmit limit reached; giving up")
                        del self.unacked[seq]
                        continue
                    # retransmit
                    self.iface.send_ip(self.dst_ip, TCP_PROTO, seg.to_bytes())
                    self.unacked[seq] = (seg, now, attempts + 1)
                    log(self.owner_name, f"Retransmitted seq={seq} attempt={attempts+1}")

    def close(self):
        self.alive = False


# ---------------------------
# Host (combines layers + socket-like API)
# ---------------------------
class Host:
    def __init__(self, name: str, ip: str, medium: PhysicalMedium):
        self.name = name
        self.mac = gen_mac()
        self.ip = ip
        self.iface = NetInterface(name, self.mac, ip, medium)
        self.iface.ip_in_callback = self._ip_in
        self.tcp_listeners: Dict[int, TCPConnection] = {}  # port -> TCPConnection (passive)
        self.tcp_connections: Dict[Tuple[int, str, int], TCPConnection] = {}  # (src_port,dst_ip,dst_port)
        self.udp_handlers: Dict[int, callable] = {}
        self.lock = threading.Lock()
        # start a retransmit timer thread
        self._retransmit_thread = threading.Thread(target=self._retransmit_loop, daemon=True)
        self._retransmit_thread.start()
        log(self.name, f"Host initialized IP={ip} MAC={self.mac}")

    def listen_tcp(self, port: int):
        conn = TCPConnection(self.name, self.iface, port, None, None, passive=True)
        conn.state = TCPState.LISTEN
        self.tcp_listeners[port] = conn
        log(self.name, f"Listening on TCP port {port}")
        return conn

    def connect_tcp(self, src_port: int, dst_ip: str, dst_port: int):
        conn = TCPConnection(self.name, self.iface, src_port, dst_ip, dst_port, passive=False)
        key = (src_port, dst_ip, dst_port)
        self.tcp_connections[key] = conn
        conn.active_open()
        return conn

    def send_udp(self, src_port: int, dst_ip: str, dst_port: int, data: bytes):
        seg = UDPSegment(src_port, dst_port, data)
        self.iface.send_ip(dst_ip, UDP_PROTO, seg.to_bytes())

    def register_udp_handler(self, port: int, callback):
        self.udp_handlers[port] = callback

    def _ip_in(self, ip_pkt: IPPacket, src_mac: str):
        # demultiplex by proto
        if ip_pkt.proto == UDP_PROTO:
            udp = UDPSegment.from_bytes(ip_pkt.payload)
            handler = self.udp_handlers.get(udp.dst_port)
            if handler:
                handler(udp.src_port, ip_pkt.src_ip, udp.data)
            else:
                log(self.name, f"No UDP handler for port {udp.dst_port}")
        elif ip_pkt.proto == TCP_PROTO:
            seg = TCPSegment.from_bytes(ip_pkt.payload)
            # route to passive listener or established conn
            # check passive listeners
            for port, listener in list(self.tcp_listeners.items()):
                if port == seg.dst_port:
                    # map a new connection object for this 4-tuple (we keep listener separate)
                    # create a new conn object to represent peer side
                    conn = TCPConnection(self.name, self.iface, seg.dst_port, ip_pkt.src_ip, seg.src_port, passive=True)
                    # Important: for simulation we will hand segment to the listener's connection handling
                    # But better: deliver to existing listener object by invoking its handler
                    listener.handle_incoming(seg)
                    # register ephemeral connection if it transitioned to ESTABLISHED
                    if listener.state == TCPState.ESTABLISHED:
                        # wrap as active conn for server side (very simplified)
                        passive_key = (seg.dst_port, ip_pkt.src_ip, seg.src_port)
                        self.tcp_connections[passive_key] = listener
                        log(self.name, f"Server accepted connection {passive_key}")
                    return
            # otherwise lookup established by key
            key = None
            # try direct key match
            k1 = (seg.dst_port, ip_pkt.src_ip, seg.src_port)
            k2 = (seg.src_port, ip_pkt.dst_ip, seg.dst_port)  # some permutations
            found = None
            for k, v in self.tcp_connections.items():
                if k == (seg.dst_port, ip_pkt.src_ip, seg.src_port) or k == (seg.src_port, ip_pkt.dst_ip, seg.dst_port):
                    found = v
                    break
            if found:
                found.handle_incoming(seg)
            else:
                # maybe an active opener (client)
                for k, v in self.tcp_connections.items():
                    if k[0] == seg.dst_port and k[1] == ip_pkt.src_ip and k[2] == seg.src_port:
                        v.handle_incoming(seg)
                        return
                log(self.name, f"No TCP endpoint for segment dstport={seg.dst_port} from {ip_pkt.src_ip}")

    def _retransmit_loop(self):
        while True:
            time.sleep(0.1)
            with self.lock:
                for conn in list(self.tcp_connections.values()):
                    conn.poll_retransmit()
                for listener in list(self.tcp_listeners.values()):
                    listener.poll_retransmit()


# ---------------------------
# Simple Application Layer Examples
# ---------------------------
def simulated_http_exchange(client: Host, server: Host, server_port=80):
    """
    Perform a tiny "HTTP-like" request over our simulated TCP:
    - server listens
    - client connects, sends GET, server responds
    """
    # server sets up listening
    server.listen_tcp(server_port)

    # connect from client ephemeral port 50000
    c = client.connect_tcp(50000, server.ip, server_port)

    # Wait for handshake to finish (in a real stack we'd block; here poll a bit)
    for _ in range(50):
        if c.state == TCPState.ESTABLISHED:
            break
        time.sleep(0.05)

    if c.state != TCPState.ESTABLISHED:
        log("APP", "Connection failed to establish")
        return

    # client sends GET
    req = b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n"
    c.send_data(req)

    # allow server to process; on server side, the listener's app buffer is where data lands
    time.sleep(0.2)

    # find server's connection object in its host table
    # (this is simplified because the server stored a connection keyed by (port, client_ip, client_port))
    server_key = (server_port, client.ip, 50000)
    srv_conn = server.tcp_connections.get(server_key)
    if not srv_conn:
        log("APP", "Server didn't create connection object; can't respond in this simulation.")
        return

    # server sees data in its app_recv_buffer
    req_text = srv_conn.app_recv_buffer.decode("utf-8", errors="ignore")
    log("APP", f"Server received request: {req_text.strip().splitlines()[0]}")

    # server sends a simple HTTP-like response
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
    # server must send using its connection object: note that for simplicity, server's src_port is server_port
    srv_conn.send_data(resp)

    # client should receive ACKs and data; wait and then print client's buffer
    time.sleep(0.3)
    log("APP", f"Client buffer (simulated): {c.app_recv_buffer.decode('utf-8', errors='ignore')}")


def real_localhost_echo_demo(port=12345):
    """
    Demonstrate a real socket echo server on localhost so you can contrast simulated vs real stacks.
    This starts a thread that listens on localhost:port, echoes incoming data, and demonstrates a client send.
    """
    def server_thread():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))
            s.listen(1)
            log("REAL", f"Real echo server listening on 127.0.0.1:{port}")
            conn, addr = s.accept()
            with conn:
                log("REAL", f"Connection from {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    conn.sendall(data)
                log("REAL", "Connection closed")

    def client_thread():
        time.sleep(0.2)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", port))
            s.sendall(b"hello over real TCP")
            data = s.recv(1024)
            log("REAL", f"Client received: {data}")

    t1 = threading.Thread(target=server_thread, daemon=True)
    t2 = threading.Thread(target=client_thread, daemon=True)
    t1.start(); t2.start()
    time.sleep(0.6)  # let threads run briefly


# ---------------------------
# Demo Topology & Runner
# ---------------------------
def demo():
    """
    Build a tiny topology:
    client (10.0.0.2) --- medium --- router --- medium --- server (10.0.1.2)
    We will show ARP, routing, TCP handshake, data exchange.
    """
    medium = PhysicalMedium("PHY", drop_rate=0.05, avg_delay=0.02, jitter=0.01)

    # Create hosts
    client = Host("Client", "10.0.0.2", medium)
    server = Host("Server", "10.0.1.2", medium)
    router = SimpleRouter("Router", medium)

    # Router interfaces (two nets)
    r_if1 = router.add_interface("10.0.0.1", gen_mac())
    r_if2 = router.add_interface("10.0.1.1", gen_mac())

    # Host interfaces already created inside Host (they used the medium and mac/ip)
    # Add routes on router
    router.add_route("10.0.0.0", 24, "10.0.0.1")
    router.add_route("10.0.1.0", 24, "10.0.1.1")

    # Create simplistic ARP entries for router to talk to hosts (in real network ARP would resolve)
    # Actually we want to let ARP happen; keep empty to demonstrate ARP handshake.
    # Start a simulated HTTP exchange from client to server
    time.sleep(0.2)
    log("DEMO", "Starting simulated HTTP exchange (client -> server).")
    simulated_http_exchange(client, server, server_port=80)

    time.sleep(0.5)
    log("DEMO", "Starting real localhost echo demo for contrast.")
    real_localhost_echo_demo()

    # Let threads settle
    time.sleep(1.0)
    log("DEMO", "Demo complete. You can inspect printed logs above.")


if __name__ == "__main__":
    demo()
