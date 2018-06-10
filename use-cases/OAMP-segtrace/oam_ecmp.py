#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket, icmp, struct, pickle
from daemonize import Daemonize
import ctypes as ct
from time import sleep

import traceback

# Needed for the simulation in our virtualized network (validation.sh).
# In a real use-case, the routing daemon would fill the eBPF map with the global addresses
LOCAL_GLOBAL_MAP = {
    'fe80::23b':'fc00::3:0',
    'fe80::24b':'fc00::4:0',
    'fe80::35b':'fc00::5:0',
    'fe80::36b':'fc00::6:0',
}

PID = "/tmp/seg6_oam_{}.pid"
sid, iface = None, None

def ip_str_to_ct(s):
    return (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, s))

def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("SEG6_OAM", 19) # TODO

    fds = []
    fds.append(b["link_local_table"].map_fd)

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

    for laddr, gaddr in LOCAL_GLOBAL_MAP.items():
        _ = lambda x: socket.inet_pton(socket.AF_INET6, x)
        logger.info("{}:{}".format(laddr, gaddr))
        bpf["link_local_table"][ip_str_to_ct(laddr)] = ip_str_to_ct(gaddr)

    while 1:
        bpf.kprobe_poll()
        sleep(0.01) # tune polling frequency here

if len(sys.argv) < 3:
    print("Format: ./oam_ecmp.py SID DEV [ll-db]")
    sys.exit(1)

sid,iface = sys.argv[1:3]
bpf, fds = install_rt('oam_ecmp_bpf.c')
rt_name = sid.replace('/','-')

if len(sys.argv) >= 4:
    f = open(sys.argv[3], 'rb')
    LOCAL_GLOBAL_MAP = pickle.load(f)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/tmp/seg6_oam_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s: [%(levelname)s] %(message)s", "%b %e %H:%M:%S")
fh.setFormatter(formatter)

logger.info(repr(LOCAL_GLOBAL_MAP))

daemon = Daemonize(app="seg6-oam", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)
print("SRv6 OAM daemon forked to background.")

daemon.start()
