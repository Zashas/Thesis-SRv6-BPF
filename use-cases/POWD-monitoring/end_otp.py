#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket, os, struct
from daemonize import Daemonize
import ctypes as ct
from time import sleep

socket.SO_TIMESTAMPING = 37
socket.SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3)
socket.SOF_TIMESTAMPING_SOFTWARE = (1<<4)

dir_path = os.path.dirname(os.path.realpath(__file__))
PID = "/tmp/end_otp_{}.pid"
sid, iface = None, None

# For RX software timestamping to be done in kernel, at least on socket with
# SOF_TIMESTAMPING_RX_SOFTWARE must be created (even without a bind or connect).
def open_rx_tstamp_sock():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    flags = socket.SOF_TIMESTAMPING_SOFTWARE | socket.SOF_TIMESTAMPING_RX_SOFTWARE
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_TIMESTAMPING, struct.pack('I', 24))

    return sock

def handle_oob_request(cpu, data, size):
    class OOBRequest(ct.Structure):
        _fields_ =  [ ("tlv_dm", ct.c_ubyte * 48),
                      ("uro_type", ct.c_ubyte),
                      ("uro_len", ct.c_ubyte),
                      ("uro_dport", ct.c_ushort),
                      ("uro_daddr", ct.c_ubyte * 16),
                      ("skb", ct.c_ubyte * (size - ct.sizeof(ct.c_ubyte * 68))) ]

    logger.info("got req");
    req = ct.cast(data, ct.POINTER(OOBRequest)).contents
    uro_port = socket.ntohs(req.uro_dport)
    uro_ip = socket.inet_ntop(socket.AF_INET6, bytes(req.uro_daddr))

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect((uro_ip, uro_port))
        sock.send(bytes(req.tlv_dm))
        sock.close()
    except Exception as e:
        logger.error("Could not sent out-of-band DM reply to ({}, {}): {}".format(uro_ip, uro_port, e))
        
def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("End_OTP", 19) # TODO

    fds = []
    fds.append(b["oob_dm_requests"].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    
    encap = {'type':'seg6local', 'action':'bpf', 'bpf':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=sid, oif=idx, encap=encap)
    
    return b, fds

def remove_rt(sig, fr):
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.route("del", dst=sid, oif=idx)
    sys.exit(0)

def run_daemon(bpf):
    signal.signal(signal.SIGTERM, remove_rt)
    signal.signal(signal.SIGINT, remove_rt)
    sock = open_rx_tstamp_sock() # keep a local variable here, otherwise Python's GC will close the sock

    bpf["oob_dm_requests"].open_perf_buffer(handle_oob_request)

    while 1:
        bpf.kprobe_poll()
        sleep(0.01) # tune polling frequency here

if len(sys.argv) < 3:
    print("Format: ./end_otp.py SID DEV")
    sys.exit(1)

sid,iface = sys.argv[1:3]
bpf, fds = install_rt(os.path.join(dir_path, 'end_otp_bpf.c'))
rt_name = sid.replace('/','-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/tmp/end_otp_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s: %(message)s",
                                              "%b %e %H:%M:%S")
fh.setFormatter(formatter)

daemon = Daemonize(app="end_otp", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)

print("End.OTP daemon forked to background.")
daemon.start()
