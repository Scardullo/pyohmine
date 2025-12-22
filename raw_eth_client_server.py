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
