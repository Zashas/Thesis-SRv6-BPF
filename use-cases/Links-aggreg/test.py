import sys, logging, signal, socket, os, socket, math, struct
import ctypes as ct
from functools import reduce

class DM_TLV(ct.Structure):
    _pack_ = 1 
    _fields_ =  [ ("type", ct.c_uint8),
                  ("len", ct.c_uint8),
                  ("reserved", ct.c_ushort),

                  ("version", ct.c_uint8, 4),
                  ("flags", ct.c_uint8, 4),
                  ("cc", ct.c_uint8),
                  ("reserved2", ct.c_ushort),

                  ("qtf", ct.c_uint8, 4),
                  ("rtf", ct.c_uint8, 4),
                  ("rtpf", ct.c_uint32, 4),
                  ("reserved3", ct.c_uint32, 20),

                  ("session_id", ct.c_uint32, 24),
                  ("tc", ct.c_uint32, 8),

                  ("timestamp1", ct.c_uint64),
                  ("timestamp2", ct.c_ulonglong),
                  ("timestamp3", ct.c_ulonglong),
                  ("timestamp4", ct.c_ulonglong) ]

class Node:
    sid, sid_bytes = "", b""
    otp_sid, otp_sid_bytes = "", b""
    weight = 0
    delay_down, delay_up = 0, 0

    def __init__(self, sid, otp_sid, weight):
        self.sid, self.otp_sid = sid, otp_sid
        self.otp_sid_bytes = socket.inet_pton(socket.AF_INET6, otp_sid)
        self.sid_bytes = socket.inet_pton(socket.AF_INET6, sid)
        self.weight = int(weight)

    def update_delays(self, delay_down, delay_up):
        self.delay_down, self.delay_up = delay_down, delay_up

def send_delay_probe(node):
    src = "fc00::2"
    src = "::1"
    src_rcv = "fc00::2a"

    segments = (bytes(16), node.otp_sid_bytes, node.sid_bytes)

    dm = DM_TLV()
    dm.type = 7
    dm.len = 46
    dm.version = 1
    dm.cc = 0
    dm.qtf = 3
    dm.timestamp1 = 42
    dm.session_id = 10

    hdrlen = (len(bytes(dm)) + len(segments) * 16) >> 3
    srh_base = struct.pack("!BBBBBBH", 0, hdrlen, 4, len(segments) - 1, len(segments) - 1, 0, 0)
    srh = srh_base + reduce(lambda x,y: x+y, segments) + bytes(dm)
    
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, srh)

    sock.bind((src, 53))
    sock.sendto(b"", (src_rcv, 53)) # Port number is irrelevant for ICMP

n = Node("fc00::3a", "fc00::3c", 1)
send_delay_probe(n)
