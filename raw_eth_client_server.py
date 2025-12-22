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
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
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
