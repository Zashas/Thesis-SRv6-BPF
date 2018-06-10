#!/usr/bin/python3
import socket, struct, queue, enum, random, sys, icmp
import ctypes as ct

ICMP_ECHO_REQ = 128
ICMP_OAM_REQ = 100
TRACERT_PORT = 33434
RTHDR_TYPE = 4
SR6_TLV_OAM_NH_REQ = 100
SR6_TLV_OAM_NH_REPLY = 101
SR6_TLV_PADDING = 4
SRH_FLAG_OAM = 32
TLV_OAM_RD = 1
TRIES_PER_PROBE = 3

# Build the GNU timeval struct (seconds, microseconds)
TIMEOUT = struct.pack("ll", 1, 0)
MAX_HOPS = 8

nb_sends = 0

class NodeType(enum.Enum):
    UNKNOWN = 0
    IPV6 = 1 # Regular IPv6 node
    SEG6 = 2 # SRv6 + OAM ECMP

    def __str__(self):
        if self.value == 1:
            return 'IP'
        elif self.value == 2:
            return 'SR'
        
        return 'UNKNOWN'
    
class Node:
    type = NodeType.UNKNOWN
    addr = ''
    name = None
    error = False

    def __init__(self, type, addr=addr):
        self.type = type
        self.addr = addr

        try:
            self.name = socket.gethostbyaddr(addr)[0]
        except socket.error as e:
            self.name = None

    def __eq__(self, other):
        _ = lambda x: socket.inet_pton(socket.AF_INET6, x)
        if isinstance(other, str):
            if self.type == NodeType.UNKNOWN:
                return False
            return (_(self.addr) == _(other))

        if self.type != other.type:
            return False

        return (_(self.addr) == _(other.addr))

    def __str__(self):
        if self.type == NodeType.UNKNOWN:
            return "*"

        if self.name:
            return "{} ({} / {})".format(self.name, self.addr, str(self.type))
        else:
            return "{} ({})".format(self.addr, str(self.type))

    def __repr__(self):
        return "<Node: {}>".format(self.__str__())

def build_srh(dst, segments):
    segments = [dst] + segments[::-1]
    ct_segments = ct.c_ubyte * 16 * len(segments)

    class SRH(ct.Structure):
        _fields_ =  [ ("nh", ct.c_uint8),
                      ("hdr_len", ct.c_uint8),
                      ("type", ct.c_uint8),
                      ("segleft", ct.c_uint8),
                      ("lastentry", ct.c_uint8),
                      ("flags", ct.c_ubyte),
                      ("tag", ct.c_ushort),
                      ("segments", ct_segments) ]

    srh = SRH(type=RTHDR_TYPE, segleft=len(segments)-1, lastentry=len(segments)-1)
    srh.hdr_len = (len(bytes(srh)) >> 3) - 1
    srh.segments = ct_segments.from_buffer_copy(b''.join([socket.inet_pton(socket.AF_INET6, s) for s in segments]))
    return srh


def send_oam_probe(src, dst, target):
    oam_dst = socket.inet_pton(socket.AF_INET6, dst) # for the replier, regular SID -> OAM SID
    oam_dst = oam_dst[:-2] + b'\x00\x08'
    oam_dst = socket.inet_ntop(socket.AF_INET6, oam_dst)
    segments = [src, oam_dst]
    ct_segments = ct.c_ubyte * 16 * 2

    class SRH_OAM_REQ(ct.Structure):
        _fields_ =  [ ("nh", ct.c_uint8),
                      ("hdr_len", ct.c_uint8),
                      ("type", ct.c_uint8),
                      ("segleft", ct.c_uint8),
                      ("lastentry", ct.c_uint8),
                      ("flags", ct.c_ubyte),
                      ("tag", ct.c_ushort),
                      ("segments", ct_segments),
                      ("tlv_oam_type", ct.c_uint8),
                      ("tlv_oam_len", ct.c_uint8),
                      ("tlv_oam_sessid", ct.c_ushort),
                      ("tlv_oam_target", ct.c_ubyte * 16),
                      ("tlv_pad_type", ct.c_uint8),
                      ("tlv_pad_len", ct.c_uint8),
                      ("tlv_pad", ct.c_ushort),
                      ]

    srh = SRH_OAM_REQ(type=RTHDR_TYPE, segleft=len(segments)-1, lastentry=len(segments)-1, flags=SRH_FLAG_OAM,
                     tlv_oam_type=SR6_TLV_OAM_NH_REQ, tlv_oam_len=18,
                     tlv_pad_type=SR6_TLV_PADDING, tlv_pad_len=2, tlv_pad=0)
    srh.hdr_len = (len(bytes(srh)) >> 3) - 1
    srh.segments = ct_segments.from_buffer_copy(b''.join([socket.inet_pton(socket.AF_INET6, s) for s in segments]))
    #srh.segment2 = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, oam_dst))
    srh.tlv_oam_target = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, target))
    sessid = random.randrange(0, 65535)
    srh.tlv_oam_sessid = sessid

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, bytes(srh))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVRTHDR, 1)
    sock.bind((src, 4242))

    global nb_sends
    try:
        sock.sendto(b"foobar", (src, 4242))
        nb_sends += 1
    except OSError:
        return None

    tries = TRIES_PER_PROBE
    while tries > 0:
        try:
            msg, ancdata, flags, addr = sock.recvmsg(100, 512)
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_RTHDR:
                    try:
                        return parse_oam_reply(cmsg_data, sessid)
                    except ValueError:
                        pass
        except socket.error as e:
            pass

        tries -= 1
    sock.close()
    
    #payload = struct.pack('!HBB', sessid, 0, 0)
    #icmp.send(src, segments[0], ICMP_OAM_REQ, 0, payload, srh=bytes(srh))
    return None

def parse_oam_reply(bare_reply, req_sessid):
    class SRH_OAM_Reply(ct.Structure):
        _fields_ =  [ ("nh", ct.c_uint8),
                      ("hdr_len", ct.c_uint8),
                      ("type", ct.c_uint8),
                      ("segleft", ct.c_uint8),
                      ("lastentry", ct.c_uint8),
                      ("flags", ct.c_ubyte),
                      ("tag", ct.c_ushort),
                      ("segments", ct.c_ubyte * 16 * 2),
                      ("tlv_oam_type", ct.c_uint8),
                      ("tlv_oam_len", ct.c_uint8),
                      ("tlv_oam_sessid", ct.c_ushort),
                      ("tlv_oam_target", ct.c_ubyte * 16),
                      ("tlv_oam2_type", ct.c_uint8),
                      ("tlv_oam2_len", ct.c_uint8),
                      ("tlv_oam2_nh", ct.c_uint8),
                      ("tlv_oam2_reserved", ct.c_uint8),
                      # nexthops here ...
                      ]

    if len(bare_reply) <= ct.sizeof(SRH_OAM_Reply):
        raise ValueError

    reply = SRH_OAM_Reply.from_buffer_copy(bare_reply)
    if reply.tlv_oam_sessid != req_sessid:
        raise ValueError

    if reply.tlv_oam2_type != SR6_TLV_OAM_NH_REPLY:
        raise ValueError

    if len(bare_reply) < ct.sizeof(SRH_OAM_Reply) + 16 * reply.tlv_oam2_nh:
        raise ValueError

    if reply.tlv_oam2_nh == 0:
        return []

    hops = bare_reply[ct.sizeof(SRH_OAM_Reply):ct.sizeof(SRH_OAM_Reply) + 16 * reply.tlv_oam2_nh]
    hops = [hops[x:x+16] for x in range(0, len(hops), 16)]
    hops = list(map(lambda x: Node(NodeType.IPV6, socket.inet_ntop(socket.AF_INET6, x)), hops))
    return hops

def new_recv_icmp_sock(allowed=None):
    rcv_icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    rcv_icmp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT)

    if allowed:
        # icmp6_filter is a bitmap, ICMP packets of type 1 are passing if the first bit is set to 0, etc..
        icmp6_filter = [255]*32 # by default, block all
        for type in allowed:
            icmp6_filter[type >> 3] &= ~(1 << ((type) & 7))

        # socket.ICMPV6_FILTER is not defined, but its value is 1 as of Linux 4.16
        rcv_icmp.setsockopt(socket.IPPROTO_ICMPV6, 1, bytes(icmp6_filter))

    return rcv_icmp

def send_udp_probe(src, dst, hops, srh, sport):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hops)
    if srh:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, srh)

    sock.bind((src, sport))
    sock.sendto(b"foo", (dst, 33434))
    global nb_sends
    nb_sends += 1
    sock.close()
    
def segtrace(src, target):
    paths = queue.Queue()
    paths.put([])
    final_paths = []

    while not paths.empty(): # unfinished paths
        path = paths.get()
        nexthops = []
        segments = [n.addr for n in path if n.type != NodeType.UNKNOWN]

        # Sending SRv6 OAM probes
        if len(path) > 0 and path[-1].type != NodeType.UNKNOWN:
            ecmp_hops = send_oam_probe(src, path[-1].addr, target)
            if ecmp_hops != None:
                path[-1].type = NodeType.SEG6
                nexthops = ecmp_hops
                
        # If the next hops are still not discovered, sending UDP probes
        if not nexthops:
            tries = TRIES_PER_PROBE
        else:
            tries = 0

        sock_recv= new_recv_icmp_sock(allowed=(1,3,129))
        while tries > 0:
            send_udp_probe(src, target, len(path) + 1, \
                    build_srh(target, segments) if segments else None, 33434 + TRIES_PER_PROBE - tries) 
            #icmp.send(src, target, ICMP_ECHO_REQ, 0, b"\x42\x42\x00\x01", hops=len(path) + 1, \
            #          srh=build_srh(target, segments) if segments else None)
            try:
                reply, replier = sock_recv.recvfrom(512)
                new_nh = Node(NodeType.IPV6, replier[0])
                if new_nh not in nexthops:
                    nexthops.append(new_nh)
            except socket.error as e:
                pass

            tries -= 1
        sock_recv.close()

        if not nexthops: # if still no data, we put it as unknown and keep going
            nexthops = [Node(NodeType.UNKNOWN)]

        for node in nexthops:
            new_path = path + [node]
            if node == target or len(new_path) >= MAX_HOPS:
                final_paths.append(new_path)
            else:
                paths.put(new_path)

    l = None
    for p in final_paths:
        if l != None and l != len(p):
            print("FAIL !")
        l = len(p)
    #    print("\n -> ".join(map(str, p)))
    #    print("")
    print("{},{},{},{},{}".format(_src,_dst,len(final_paths),nb_sends,l))

if __name__ == "__main__":
    src,dst = None, None
    if len(sys.argv) >= 3:
        _src, _dst = sys.argv[1:3]
        try:
            socket.inet_pton(socket.AF_INET6, _src)
            socket.inet_pton(socket.AF_INET6, _dst)
            src, dst = _src, _dst
        except:
            pass

    if not src or not dst:
        print("Usage: segtrace.py bindaddr target")
        sys.exit(1)

    segtrace(src, dst)
