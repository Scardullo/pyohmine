#!/usr/bin/env python3

import socket
import struct
import random
import time 
import argparse 
import select
import sys
import fcntl
import os

ETH_P_ALL = 0x0003 
ETH_P_IP = 0x0800 
ETH_P_ARP = 0x0806

SIOCGIFHWADDR = 0x8927
SIOCGIFADDR = 0x8915
SIOCGIFINDEX = 0x8933


def mac_str_to_bytes(mac_str: str) -> bytes:
    return bytes(int(x, 16) for x in mac_str.split(':'))

def mac_bytes_to_str(b: bytes) -> str:
    return ':'.join('{:02x}'.format(x) for x in b)

def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)

def bytes_to_ip(b: bytes) -> str:
    return socket.inet_ntoa(b)

def get_iface_mac(ifname: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname.encode('utf-8')[:15])
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    mac = struct.unpack('256s', res)[0][18:24]
    return mac_bytes_to_str(mac)

def get_iface_ip(ifname: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname.encode('utf-8')[:15])
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
    except OSError:
        return None
    ip = struct.unpack('256s', res)[0][20:24]
    return bytes_to_ip(ip)

def get_iface_index(ifname: str) -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname.encode('utf-8')[:15])
    res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
    idx = struct.unpack('I', res[16:20])[0]
    return idx

def ipv4_checksum(header_bytes: bytes) -> int:
    if len(header_bytes) % 2:
        header_bytes += b'\x00'
    s = 0
    for i in range(0, len(header_bytes), 2):
        w = (header_bytes[i] << 8) + header_bytes[i+1]
        s += w
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_checksum(src_ip: str, dst_ip: str, tcp_header_and_payload: bytes) -> int:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header_and_payload)
    pseudo_header = src + dst + struct.pack('!BBH', placeholder, protocol, tcp_length)
    total = pseudo_header + tcp_header_and_payload
    if len(total) % 2:
        total += b'\x00'
    s = 0
    for i in range(0, len(total), 2):
        w = (total[i] << 8) + total[i+1]
        s += w
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def build_ethernet_header(dst_mac: bytes, src_mac: bytes, ethertype: int) -> bytes:
    return struct.pack('!6s6sH', dst_mac, src_mac, ethertype)

def parse_ethernet_frame(frame: bytes):
    if len(frame) < 14:
        return None
    dst = frame[0:6]
    src = frame[6:12]
    ethertype = struct.unpack('!H', frame[12:14])[0]
    payload = frame[14:]
    return (dst, src, ethertype, payload)

def build_arp_request(src_mac: bytes, src_ip: str, target_ip: str) -> bytes:
    htype = 1
    ptype = 0x0800
    hlen = 6
    plen = 4
    opcode = 1

    arp_pkt = struct.pack(
        '!HHBBH6s4s6s4s',
        htype, ptype, hlen, plen, opcode,
        src_mac, socket.inet_aton(src_ip), b'\x00'*6, socket.inet_aton(target_ip)
    )
    return arp_pkt

def build_arp_reply(src_mac: bytes, src_ip: str, target_mac: bytes, target_ip: str) -> bytes:
    htype = 1
    ptype = 0x0800
    hlen = 6
    plen = 4
    opcode = 2

    arp_pkt = struct.pack(
        '!HHBBH6s4s6s4s',
        htype, ptype, hlen, plen, opcode,
        src_mac, socket.inet_aton(src_ip), target_mac, socket.inet_aton(target_ip)
    )
    return arp_pkt

def parse_arp_packet(payload: bytes):
    if len(payload) < 28:
        return None
    
    htype, ptype, hlen, plen, opcode = struct.unpack('!HHBBH', payload[:8])
    sha = payload[8:14]
    spa = socket.inet_ntoa(payload[14:18])
    tha = payload[18:24]
    tpa = socket.inet_ntoa(payload[24:28])

    return {
        'htype': htype, 'ptype': ptype, 'hlen': hlen, 'plen': plen, 'opcode': opcode,
        'sha': sha, 'spa': spa, 'tha': tha, 'tpa': tpa    
    }

def build_ip_header(src_ip: str, dst_ip: str, payload_len: int,
                    identification=None, ttl=64, proto=socket.IPPROTO_TCP):
    
    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    tos = 0
    total_length = 20 + payload_len
    identification = identification if identification is not None else random.randrange(0, 0xffff)
    flags_fragment = 0
    ttl = ttl
    proto = proto
    checksum = 0

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header_wo_checksum = struct.pack(
        '!BBHHHBBH4s4s',
        ver_ihl, tos, total_length, identification, flags_fragment,
        ttl, proto, checksum, src, dst
    )

    checksum = ipv4_checksum(header_wo_checksum)

    header = struct.pack(
        '!BBHHHBBH4s4s', ver_ihl, tos, total_length, identification, flags_fragment,
        ttl, proto, checksum, src, dst
    )

    return header

def build_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int,
                     flags: dict, window=5840, payload=b'', options=b''):
    
    data_offset = 5 + (len(options) + 3) // 4
    offset_reserved_flags = (data_offset << 12)

    flag_bits = 0
    flag_map = {'FIN':0x001, 'SYN':0x002, 'RST':0x004, 'PSH':0x008, 'ACK':0x010, 'URG':0x020}

    for k, v in flags.items():
        if v and k in flag_map:
            flag_bits |= flag_map[k]

    offset_reserved_flags |= flag_bits

    urg_ptr = 0
    checksum = 0

    tcp_header_wo_checksum = struct.pack(
        '!HHLLHHHH', src_port, dst_port, seq, ack,
        offset_reserved_flags, window, checksum, urg_ptr
    )

    if options:
        opt_pad_len = (4 - (len(options) % 4)) % 4
        options_padded = options + (b'\x00' * opt_pad_len)
    else:
        options_padded = b''

    tcp_segment = tcp_header_wo_checksum + options_padded + payload

    checksum = tcp_checksum(src_ip, dst_ip, tcp_segment)

    tcp_header = struct.pack(
        '!HHLLHHHH', src_port, dst_port, seq, ack, 
        offset_reserved_flags, window, checksum, urg_ptr
    )

    tcp_header = tcp_header + options_padded

    return tcp_header

def parse_ipv4_packet(packet: bytes):
    if len(packet) < 20:
        return None
    vihl, tos, total_lenght, identification, flags_fragment, ttl, proto, checksum, src, dst, = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    version = vihl >> 4
    ihl = (vihl & 0x0f) * 4
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    payload = packet[ihl:total_length]
    return (ihl, proto, src_ip, dst_ip, payload, total_length, identification, flags_fragment, ttl)

def parse_tcp_segment(segment: bytes):
    if len(segment) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', segment[:20])
    data_offset = (offset_reserved_flags >> 12) * 4
    flag_bits = offset_reserved_flags & 0x01FF
    flags = {
        'FIN': bool(flag_bits & 0x001),
        'SYN': bool(flag_bits & 0x002),
        'RST': bool(flag_bits & 0x004),
        'PSH': bool(flag_bits & 0x008),
        'ACK': bool(flag_bits & 0x010),
        'URG': bool(flag_bits & 0x020),
    }
    payload = segment[data_offset:]
    return (src_port, dst_port, seq, ack, data_offset, flags, window, checksum, urg_ptr, payload)

def create_af_packet_socket(ifname: str):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((ifname, 0))
    return s


class EthernetDriver:
    def __init__(self, ifname: str, my_mac: str=None, my_ip: str=None, timeout=5.0):
        self.ifname = ifname
        self.timeout = timeout
        self.sock = create_af_packet_socket(ifname)
        self.ifindex = get_iface_index(ifname)
        self.my_mac_str = my_mac if my_mac else get_iface_mac(ifname)
        self.my_ip = my_ip if my_ip else get_iface_ip(ifname)
        self.my_mac = mac_str_to_bytes(self.my_mac_str)
        if not self.my_ip:
            raise RuntimeError(f"Could not determine IP of interface {ifname}.")
        self.arp_cache = {}

    def send_frame(self, dst_mac_bytes: bytes, ethertype: int, payload: bytes):
        eth = build_ethernet_header(dst_mac_bytes, self.my_mac, ethertype)
        frame = eth + payload
        self.sock.send(frame)

    def recv_frame(self, timeout=None):
        timeout = timeout if timeout is not None else self.timeout
        rlist, _, _ = select.select([self.sock], [], [], timeout)
        if not rlist:
            return None
        frame = self.sock.recv(65535)
        parsed = parse_ethernet_frame(frame)
        return parsed
    
    def resolve_arp(self, target_ip: str, retry=3, wait=2.0):
        if target_ip in self.arp_cache:
            return self.arp_cache[target_ip]
        
        dst_mac = b'\xff'*6
        arp_req = build_arp_request(self.my_mac, self.my_ip, target_ip)
        eth = build_ethernet_header(dst_mac, self.my_mac, ETH_P_ARP)
        pkt = eth + arp_req
        for attempt in range(retry):
            self.sock.send(pkt)
            print(f"[+] ARP request sent for {target_ip} (attempt {attempt+1})")
            t_end = time.time() + wait
            while time.time() < t_end:
                parsed = self.recv_frame(timeout=t_end - time.time())
                if not parsed:
                    continue
                dst, src, ethertype, payload = parsed
                if ethertype == ETH_P_ARP:
                    arp = parse_arp_packet(payload)
                    if arp and arp['opcode'] == 2 and arp['spa'] == target_ip:
                        mac = arp['sha']
                        self.arp_cache[target_ip] = mac
                        print(f"[+] ARP reply: {target_ip} is at {mac_bytes_to_str(mac)}")
                        return mac
        print("[-] ARP resolution failed")
        return None
    

class RawEthernetTCPClient:
    def __init__(self, ifname: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, timeout=5.0):
        self.ifname = ifname
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.timeout = timeout
        self.eth = EthernetDriver(ifname, my_ip=src_ip, timeout=timeout)
        self.dst_mac = None
        self.isn = random.randrange(0, 0xffffffff)
        self.snd_seq = self.isn
        self.rcv_seq = None

    def ensure_dst_mac(self):
        if self.dst_mac:
            return self.dst_mac
        mac = self.eth.resolve_arp(self.dst_ip)
        if mac is None:
            raise RuntimeError("Could not resolve destination MAC via ARP")
        self.dst_mac = mac
        return mac
    
    def send_ip_tcp_frame(self, tcp_hdr: bytes, payload: bytes=b''):
        ip_hdr = build_ip_header(self.src_ip, self.dst_ip, len(tcp_hdr) + len(payload))
        eth_payload = ip_hdr + tcp_hdr + payload
        dst_mac = self.ensure_dst_mac()
        self.eth.send_frame(dst_mac, ETH_P_IP, eth_payload)

    def receive_matching_packet(self, timeout=None):
        timeout = timeout if timeout is not None else self.timeout
        t_end = time.time() + timeout
        while time.time() < t_end:
            parsed = self.eth.recv_frame(timeout=t_end - time.time())
            if not parsed:
                continue
            dst, src, ethertype, payload = parsed
            if ethertype != ETH_P_IP:
                continue
            ip_parsed = parse_ipv4_packet(payload)
            if not ip_parsed:
                continue
            ihl, proto, src_ip, dst_ip, ip_payload, total_length, identification, flags_fragment, ttl = ip_parsed
            if src_ip != self.dst_ip or dst_ip != self.src_ip:
                continue
            tcp = parse_tcp_segment(ip_payload)
            if not tcp:
                continue
            src_port, dst_port, seq, ack, data_off, flags, window, checksum, urg_ptr, payload_data = tcp
            if src_port != self.dst_port or dst_port != self.src_port:
                continue
            return {'seq': seq, 'ack': ack, 'flags': flags, 'payload': payload_data, 'window': window}
        return None
    
    def handshake(self):
        options = struct.pack('!BBH', 2, 4, 1460)
        options += b'\x01' * ((4 - (len(options) % 4)) % 4)
        syn_flags = {'SYN': True, 'ACK': False, 'RST': False, 'FIN': False, 'PSH': False, 'URG': False}
        tcp_hdr_syn = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dest_port,
                                       seq=self.snd_seq, ack=0, flags=syn_flags, window=5840, payload=b'', options=options)
        print(f"[+] Sending Ethernet/IPv4 SYN seq={self.snd_seq}")
        self.send_ip_tcp_frame(tcp_hdr_syn)

        start = time.time()
        while True:
            remaining = max(0, self.timeout - (time.time() - start))
            pkt = self.receive_matching_packet(timeout=remaining)
            if pkt is None:
                print("[-] Timeout waiting for SYN-ACK")
                return False
            if pkt['flags']['SYN'] and pkt['flags']['ACK']:
                print(f"[+] Received SYN-ACK seq={pkt['seq']} ack={pkt['ack']}")
                self.rcv_seq = pkt['seq']
                self.snd_seq += 1
                ack_num = self.rcv_seq + 1
                ack_flags = {'SYN': False, 'ACK': True, 'RST': False, 'FIN': False, 'PSH': False, 'URG': False}
                tcp_hdr_ack = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                               seq=self.snd_seq, ack=ack_num, flags=ack_flags, window=5840, payload=b'')
                print(f"[+] Sending ACK seq={self.snd_seq} ack={ack_num}")
                self.send_ip_tcp_frame(tcp_hdr_ack)
                return True
            if pkt['flags']['RST']:
                print("[-] Received RST; connection refused/reset")
                return False
            
    def send_data(self, data: bytes):
        payload = data
        flags = {'PSH': True, 'ACK': True, 'SYN': False, 'RST': False, 'FIN': False, 'URG': False}
        tcp_hdr = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                   seq=self.snd_seq, ack=self.rcv_seq+1, flags=flags, payload=payload)
        print(f"[+] Sending DATA seq={self.snd_seq} len={len(payload)}")
        self.send_ip_tcp_frame(tcp_hdr, payload=payload)
        self.snd_seq += len(payload)
        start = time.time()
        while True:
            remaining = max(0, self.timeout - (time.time() - start))
            pkt = self.receive_matching_packet(timeout=remaining)
            if pkt is None:
                print("[-] Timeout waiting for ACK to data")
                return False
            if pkt['flags']['ACK']:
                if pkt['ack'] >= self.snd_seq:
                    print(f"[+] Data acknowledged ack={pkt['ack']}")
                    return True
            if pkt['flags']['RST']:
                print("[-] Received RST after data")
                return False
            
    def close(self):
        fin_flags = {'FIN': True, 'ACK': True, 'SYN': False, 'RST': False, 'PSH': False, 'URG': False}
        tcp_hdr_fin = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                       seq=self.snd_seq, ack=self.rcv_seq+1, flags=fin_flags, payload=b'')
        print(f"[+] Sending FIN seq={self.snd_seq}")
        self.send_ip_tcp_frame(tcp_hdr_fin)
        self.snd_seq += 1
        start = time.time()
        while True:
            remaining = max(0, self.timeout - (time.time() - start))
            pkt = self.receive_matching_packet(timeout=remaining)
            if pkt is None:
                print("[-] Timeout waiting for FIN/ACK")
                return False
            if pkt['flags']['ACK'] and pkt['ack'] >= self.snd_seq:
                print(f"[+] FIN acknowledged ack={pkt['ack']}")
            if pkt['flags']['FIN']:
                ack_for_them = pkt['seq'] + 1
                ack_flags = {'ACK': True, 'SYN': False, 'RST': False, 'FIN': False, 'PSH': False, 'URG': False}
                tcp_hdr_final_ack = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                                     seq=self.snd_seq, ack=ack_for_them, flags=ack_flags, payload=b'')
                print(f"[+] Received FIN from remote seq={pkt['seq']}; sending final ack={ack_for_them}")
                self.send_ip_tcp_frame(tcp_hdr_final_ack)
                return True
            
def get_default_src_ip_for_dst(dst_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst_ip, 80))
        src_ip = s.getsockname()[0]
        s.close()
        return src_ip
    except Exception:
        return None
    

class RawIPTCPClient:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, timeout=5.0):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.timeout = timeout
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.receiver.bind((src_ip, 0))
        self.isn = random.randrange(0, 0xffffffff)
        self.snd_seq = self.isn
        self.rcv_seq = None

    def send_ip_tcp(self, tcp_hdr: bytes, payload: bytes=b''):
        ip_hdr = build_ip_header(self.src_ip, self.dst_ip, len(tcp_hdr) + len(payload))
        packet = ip_hdr + tcp_hdr + payload
        self.sender.sendto(packet, (self.dst_ip, 0))

    def recv_matching(self, timeout=None):
        timeout = timeout if timeout is not None else self.timeout
        ready = select.select([self.receiver], [], [], timeout)
        if not ready[0]:
            return None
        packet, addr = self.receiver.recvfrom(65535)
        parsed = parse_ipv4_packet(packet)
        if not parsed:
            return None
        ihl, proto, src_ip, dst_ip, payload, total_length, identification, flags_fragment, ttl = parsed
        if src_ip != self.dst_ip or dst_ip != self.src_ip:
            return None
        tcp = parse_tcp_segment(payload)
        if not tcp:
            return None
        src_port, dst_port, seq, ack, data_off, flags, window, checksum, urg_ptr, payload_data = tcp
        if src_port != self.dst_port or dst_port != self.src_port:
            return None
        return {'seq': seq, 'ack': ack, 'flags': flags, 'payload': payload_data}
    
    def handshake(self):
        options = struct.pack('!BBH', 2, 4, 1460)
        options += b'\x01' * ((4 - (len(options) % 4)) % 4)
        syn_flags = {'SYN': True, 'ACK': False, 'RST': False, 'FIN': False, 'PSH': False, 'URG': False}
        tcp_hdr_syn = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                       seq=self.snd_seq, ack=0, flags=syn_flags, window=5840, payload=b'', options=options)
        print(f"[+] Sending raw-IP SYN seq={seq.snd_seq}")
        self.send_ip_tcp(tcp_hdr_syn)
        start = time.time()
        while True:
            remaining = max(0, self.timeout - (time.time() - start))
            pkt = self.recv_matching(timeout=remaining)
            if pkt is None:
                print("[-] Timeout waiting for SYN-ACK")
                return False
            if pkt['flags']['SYN'] and pkt ['flags']['ACK']:
                print(f"[+] Received SYN-ACK seq={pkt['seq']} ack={pkt['ack']}")
                self.rcv_seq = pkt['seq']
                self.snd_seq += 1
                ack_num = self.rcv_seq + 1
                ack_flags = {'SYN': False, 'ACK': True, 'RST': False, 'FIN': False, 'PSH': False, 'URG': False}
                tcp_hdr_ack = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port, 
                                               seq=self.snd_seq, ack=ack_num, flags=ack_flags, window=5840, payload=b'')
                print(f"[+] Sending ACK seq={self.snd_seq} ack={ack_num}")
                self.send_ip_tcp(tcp_hdr_ack)
                return True
            if pkt['flags']['RST']:
                print(f"[-] Received RST; Connection refused/reset")
                return False
            
    def send_data(self, data: bytes):
        payload = data
        flags = {'PSH': True, 'ACK': True, 'SYN': False, 'RST': False, 'FIN': False, 'URG': False}
        tcp_hdr = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                   seq=self.snd_seq, ack=self.rcv_seq+1, flags=flags, payload=payload)
        print(f"[+] Sending DATA seq={self.snd_seq} len={len(payload)}")
        self.send_ip_tcp(tcp_hdr, payload=payload)
        self.snd_seq += len(payload)
        start = time.time()
        while True:
            remaining = max(0, self.timeout - (time.time() - start))
            pkt = self.recv_matching(timeout=remaining)
            if pkt is None:
                print("[-] Timeout waiting for ACK to data")
                return False
            if pkt['flags']['ACK']:
                if pkt['ack'] >= self.snd_seq:
                    print(f"[+] Data acknowledged ack={pkt['ack']}")
                    return True
            if pkt['flags']['RST']:
                print("[-] Received RST after data")
                return False
            
    def close(self):
        fin_flags = {'FIN': True, 'ACK': True, 'SYN': False, 'RST': False, 'PSH': False, 'URG': False}
        tcp_hdr_fin = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port, 
                                       seq=self.snd_seq, ack=self.rcv_seq+1, flags=fin_flags, payload=b'')
        print(f"[+] Sending FIN seq={self.snd_seq}")
        self.send_ip_tcp(tcp_hdr_fin)
        self.snd_seq += 1
        start = time.time()
        while True:
            remaining = max(0, self.timeout - (time.time() - start))
            pkt = self.recv_matching(timeout=remaining)
            if pkt is None:
                print("[-] Timeout waiting for FIN/ACK")
                return False
            if pkt['flags']['ACK'] and pkt['ack'] >= self.snd_seq:
                print(f"[+] FIN acknowledged ack={pkt['ack']}")
            if pkt['flags']['FIN']:
                ack_for_them = pkt['seq'] + 1
                ack_flags = {'ACK': True, 'SYN': False, 'RST': False, 'FIN': False, 'PSH': False, 'URG': False}
                tcp_hdr_final_ack = build_tcp_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                                                     seq=self.snd_seq, ack=ack_for_them, flags=ack_flags, payload=b'')
                print(f"[+] Received FIN from remote seq={pkt['seq']}; sending final ACK ack={ack_for_them}")
                self.send_ip_tcp(tcp_hdr_final_ack)
                return True
            

def main():
    parser = argparse.ArgumentParser(description="Raw Ethernet + ARP + IPv4 + TCP demo (Linux)")
    parser.add_argument('--ifname', help='Interface name to use for Ethernet frames (e.g. eth0). If omitted, fallback to raw IP sockets.')
    parser.add_argument('--src-ip', help='Source IPv4 address (optional). If omitted, auto-detected for interface or route.')
    parser.add_argument('--dst-ip', required=True, help='Destination IPv4 address')
    parser.add_argument('--dst-port', type=int, required=True, help='Destination TCP port')
    parser.add_argument('--payload', default='', help='Payload to send after handshake')
    parser.add_argument('--timeout', type=float, default=5.0, help='Timeoutr seconds for responses')
    args = parser.parse_args()

    if args.ifname:
        ifname = args.ifname
        try:
            iface_mac = get_iface_mac(ifname)
        except Exception as e:
            print(f"[-] Could not read MAC for interface {ifname}: {e}")
            sys.exit(1)
        src_ip = args.src_ip if args.src_ip else get_iface_ip(ifname)
        if not src_ip:
            print("[-] Could not determine interface IP. Provide --src-ip.")
            sys.exit(1)
        src_port = args.src_port if args.src_port else random.randint(1025, 65534)
        print(f"[+] Running over interface {ifname} src {src_ip} mac {iface_mac}")
        client = RawEthernetTCPClient(ifname, src_ip, args.dst_ip, src_port, args.dst_port, timeout=args.timeout)
    
    else:
        src_ip = args.src_ip if args.src_ip else get_default_src_ip_for_dst(args.dst_ip)
        if not src_ip:
            print("[-] Could not determine source IP automatically. Provide --src_ip.")
            sys.exit(1)
        src_port = args.src_port if args.src_port else random.randint(1025, 65534)
        print(f"[+] Running over raw IP src {src_ip}")
        client = RawIPTCPClient(src_ip, args.dst_ip, src_port, args.dst_port, timeout=args.timeout)

    try:
        ok = client.handshake()
        if not ok:
            print("[-] Handshake failed")
            return
        payload_bytes = args.payload.encode('utf-8')
        if payload_bytes:
            ok2 = client.send_data(payload_bytes)
            if not ok2:
                print("[-] Failed to send/receive data ack.")
        print("[*] Listening briefly for inbound data...")
        t_end = time.time() + 2.0
        while time.time() < t_end:
            if args.ifname:
                pkt = client.receive_matching_packet(timeout=0.5)
                if pkt:
                    print(f"[<] Received packet flags={pkt['flags']} seq={pkt['seq']} ack={pkt['ack']} len={len(pkt['payload'])}")
                    if pkt['payload']:
                        try:
                            print(pkt['payload'].decode('utf-8', errors='replace'))
                        except Exception:
                            print(repr(pkt['payload']))
            else:
                pkt = client.recv_matching(timeout=0.5)
                if pkt:
                    print(f"[<] Received packet flags={pkt['flags']} seq={pkt['seq']} ack={pkt['ack']} len={len(pkt['payload'])}")
                    if pkt['payload']:
                        try:
                            print(pkt['payload'].decode('utf-8', errors='replace'))
                        except Exception:
                            print(repr(pkt['payload']))
        client.close()
    except KeyboardInterrupt:
        print("[*] Interrupted by user.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        pass

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[-] This script requires root privileges. Run with sudo.")
        sys.exit(1)
    main()            
    



                