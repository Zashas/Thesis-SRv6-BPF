#!/usr/bin/python3

import sys, logging, signal, socket, os, socket, math, traceback
import struct, time, subprocess, threading, collections
import ctypes as ct
from daemonize import Daemonize
from pyroute2 import IPRoute
from functools import reduce
from bcc import BPF

PID = "/tmp/link_aggreg_{}.pid"
ROOT_QDISC = 1
PROBES_INTERVAL = 1 # in sec
LEN_DELAYS_BUFF = 1 # number of previous delay values included for the link compensation delay computation
PROBES_TTL = 50

prefix, L1, L2, sid_otp_down, sid_otp_down_bytes, sid_otp_up, sid_otp_up_bytes, logger = [None] * 8

class DaemonShutdown(Exception):
    pass

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

                  ("timestamp1_sec", ct.c_uint32),
                  ("timestamp1_nsec", ct.c_uint32),
                  ("timestamp2_sec", ct.c_uint32),
                  ("timestamp2_nsec", ct.c_uint32),
                  ("timestamp3_sec", ct.c_uint32),
                  ("timestamp3_nsec", ct.c_uint32),
                  ("timestamp4_sec", ct.c_uint32),
                  ("timestamp4_nsec", ct.c_uint32) ]

class DM_Session:
    link, batch, batch_id, delay_down, delay_up, tc_delays = None, None, None, None, None, None

    def __init__(self, link, batch, batch_id, tc_delays):
        self.link = link
        self.batch = batch
        self.batch_id = batch_id
        self.tc_delays = tc_delays

    def has_reply(self):
        if self.delay_down and self.delay_up:
            return True
        return False

    def store_delays(self, down, up):
        self.delay_down = down
        self.delay_up = up

class Link:
    id = 0
    sid_down, sid_down_bytes = "", b""
    sid_up, sid_up_bytes = "", b""
    weight = 0
    current_dm_sess_id_recv = -1
    tc_classid, tc_handle = "", ""
    delays_down, delays_up = None, None
    tc_delay_down, tc_delay_up = 0, 0 # current compensation delays set on this link

    # global vars
    nb_links = 0
    dm_sessions = collections.OrderedDict() # id -> (Link, batch_id, delay_down, delay_up)
    current_dm_sess_id_sent = 0
    last_batch_completed = -1

    def __init__(self, sid_down, sid_up, weight):
        self.id = Link.nb_links
        Link.nb_links +=1

        self.sid_down, self.sid_up = sid_down, sid_up
        self.sid_down_bytes = socket.inet_pton(socket.AF_INET6, sid_down)
        self.sid_up_bytes = socket.inet_pton(socket.AF_INET6, sid_up)
        self.weight = int(weight)

        self.tc_classids = ["{}:{}{}".format(ROOT_QDISC, self.id + 2, i) for i in range(2)] # class ids must start at 2
        self.tc_handles = ["1{}{}:".format(self.id + 2, i) for i in range(2)]
        self.tc_fwmark = str(self.id + 10)
        self.install_tc()
        self.delays_down = collections.deque([], LEN_DELAYS_BUFF)
        self.delays_up = collections.deque([], LEN_DELAYS_BUFF)

    def get_avg_delays(self):
        avg_down = sum(self.delays_down) / len(self.delays_down)
        avg_up = sum(self.delays_up) / len(self.delays_up)

        return avg_down, avg_up

    def add_delays(self, delay_down, delay_up):
        self.delays_down.append(delay_down)
        self.delays_up.append(delay_up)

    def set_tc_delays(self, delay_down, delay_up):
        self.tc_delay_down = delay_down
        self.tc_delay_up = delay_up
        delay_down_ms = "{}ms".format(int(delay_down*1000))
        delay_up_ms = "{}ms".format(int(delay_up*1000))

        for iface in ifaces_down:
            # update downlink delay compensation
            exec_cmd(["tc", "qdisc", "change", "dev", iface, "parent", self.tc_classids[0], "handle", self.tc_handles[0], "netem", "delay", delay_down_ms])

        for iface in ifaces_up:
            # update downlink delay compensation
            exec_cmd(["tc", "qdisc", "change", "dev", iface, "parent", self.tc_classids[0], "handle", self.tc_handles[0], "netem", "delay", delay_up_ms])


    def install_tc(self):
        parent = "{}:".format(ROOT_QDISC)

        # tc setup for downlink delay compensation
        #exec_cmd(["ip6tables", "-I", "FORWARD", "-d", self.sid_up, "-j", "MARK", "--set-mark", self.tc_fwmark])
        for iface in ifaces_down:
            exec_cmd(["tc", "class", "add", "dev", iface, "parent", parent, "classid", self.tc_classids[0], "htb", "rate", "1000Mbps"])
            exec_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "u32", "match", "ip6", "dst", self.sid_up, "flowid", self.tc_classids[0]])
            #exec_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "handle", self.tc_fwmark, "fw", "flowid", self.tc_classids[0]])
            exec_cmd(["tc", "qdisc", "add", "dev", iface, "parent", self.tc_classids[0], "handle", self.tc_handles[0], "netem", "delay", "0ms"])

        #exec_cmd(["ip6tables", "-I", "INPUT", "-d", self.sid_down, "-j", "MARK", "--set-mark", self.tc_fwmark])
        for iface in ifaces_up:
            exec_cmd(["tc", "class", "add", "dev", iface, "parent", parent, "classid", self.tc_classids[0], "htb", "rate", "1000Mbps"])
            exec_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "u32", "match", "ip6", "dst", self.sid_down, "flowid", self.tc_classids[0]])
            #exec_cmd(["tc", "filter", "add", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "handle", self.tc_fwmark, "fw", "flowid", self.tc_classids[0]])
            exec_cmd(["tc", "qdisc", "add", "dev", iface, "parent", self.tc_classids[0], "handle", self.tc_handles[0], "netem", "delay", "0ms"])

    def remove_tc(self):
        parent = "{}:".format(ROOT_QDISC)

        for iface in ifaces_down:
            exec_cmd(["tc", "class", "delete", "dev", iface, "parent", parent, "classid", self.tc_classids[0], "htb", "rate", "1000Mbps"], log=True)
            exec_cmd(["tc", "filter", "delete", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "u32", "match", "ip6", "dst", self.sid_up, "flowid", self.tc_classids[0]], log=True)

    class ConfigError(Exception):
        pass

def log_traceback(func):
    def f(*args, **kwargs):
        try:
            return func(*args, **kwargs) 
        except DaemonShutdown:
            kill_daemon()
        except Exception:
            logger.error(traceback.format_exc()) 

    return f

def exec_cmd(cmd, log=False):
    ret = subprocess.run(cmd, stderr=subprocess.PIPE)
    if ret.returncode:
        stderr = ret.stderr.decode('ascii').strip()
        msg = "Error executing the following shell command: {} -- {}".format(" ".join(ret.args), stderr)

        if log:
            logger.error(msg)
        else:
            raise Link.ConfigError(msg)

    return ret

def send_delay_probe(link):
    #UDP payload is never used, we just rely on the SRH
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) 
    sock.bind(('', 9999)) # TODO

    # the first segment is filled by the kernel with the address given in sendto()
    segments = (bytes(16), link.sid_down_bytes, sid_otp_up_bytes, link.sid_up_bytes)

    hdrlen = (48 + len(segments) * 16) >> 3
    srh_base = struct.pack("!BBBBBBH", 0, hdrlen, 4, len(segments) - 1, len(segments) - 1, 0, 0)

    dm = DM_TLV()
    dm.type = 7
    dm.len = 46
    dm.version = 1
    dm.cc = 0
    dm.qtf = 3
    
    ts = time.time()
    dm.timestamp1_sec = socket.htonl(int(ts))
    dm.timestamp1_nsec = socket.htonl(int((ts % 1) * 10**9))

    dm.session_id = Link.current_dm_sess_id_sent
    Link.current_dm_sess_id_sent = (Link.current_dm_sess_id_sent + 1) % (2**24)

    srh = srh_base + reduce(lambda x,y: x+y, segments) + bytes(dm)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, srh)
    sock.sendto(b"", (sid_otp_down, 9999))
    sock.close()

    return dm.session_id

class ProbesSender(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.shutdown_flag = threading.Event()

    @log_traceback
    def run(self):
        current_batch_id = 0
        while not self.shutdown_flag.is_set():
            batch = []

            for link in (L1, L2):
                sessid = send_delay_probe(link)
                session = DM_Session(link, batch, current_batch_id, (link.tc_delay_down, link.tc_delay_up))
                batch.append(session)

                Link.dm_sessions[sessid] = session

            current_batch_id += 1

            # remove unanswered probes older than PROBES_TTL batches
            for k,v in Link.dm_sessions.copy().items():
                if current_batch_id > v.batch_id + PROBES_TTL:
                    del Link.dm_sessions[k]

            time.sleep(PROBES_INTERVAL)

@log_traceback
def handle_dm_reply(cpu, data, size):
    t4 = time.time()
    def ieee_to_float(sec, nsec):
        val = float(socket.ntohl(sec))
        val += float(socket.ntohl(nsec)) / 10**9
        return val

    dm = ct.cast(data, ct.POINTER(DM_TLV)).contents
    if not dm.session_id in Link.dm_sessions:
        return
    session = Link.dm_sessions[dm.session_id]

    t1 = ieee_to_float(dm.timestamp1_sec, dm.timestamp1_nsec)
    t2 = ieee_to_float(dm.timestamp2_sec, dm.timestamp2_nsec)
    t3 = ieee_to_float(dm.timestamp3_sec, dm.timestamp3_nsec)
    session.store_delays(t2 - t1, t4 - t3)

    if session.batch_id > Link.last_batch_completed and all(map(lambda x: x.has_reply(), session.batch)):
        update_tc_delays(session.batch_id, session.batch)

def update_tc_delays(batch_id, batch):
    Link.last_batch_completed = batch_id

    for dm in batch:
        logger.debug("{}: DOWN={} UP={}".format(dm.link.sid_up, dm.delay_down - dm.tc_delays[0], dm.delay_up - dm.tc_delays[1]))
        dm.link.add_delays(dm.delay_down - dm.tc_delays[0], dm.delay_up - dm.tc_delays[1])

    delays_L1 = L1.get_avg_delays()
    delays_L2 = L2.get_avg_delays()

    compensations = ([0, 0], [0, 0]) # 2x2 delay compensation matrix
    for i in range(2): # compute delay down, then up
        if delays_L1[i] < delays_L2[i]:
            compensations[0][i] = delays_L2[i] - delays_L1[i]
        else:
            compensations[1][i] = delays_L1[i] - delays_L2[i]
        #logger.info("new delay on {}: {} = {} & {}".format(link_slow.sid_up, diff_delay, delay1, delay2))

    logger.debug("New compensation matrix: {}".format(repr(compensations)))
    logger.debug('')
    L1.set_tc_delays(*compensations[0])
    L2.set_tc_delays(*compensations[1])

def install_rt(prefix, bpf_file, bpf_func, maps):
    b = BPF(src_file=bpf_file)
    fn = b.load_func(bpf_func, 10) #BPF.LWT_IN TODO

    fds = []
    for m in maps:
        fds.append(b[m].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=ifaces_down[0])[0]
    
    encap = {'type':'bpf', 'in':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=prefix, oif=idx, encap=encap)
    
    return b, fds

def remove_setup(sig, fr):
    raise DaemonShutdown
    
def run_daemon(bpf_aggreg, bpf_dm):
    signal.signal(signal.SIGTERM, remove_setup)
    signal.signal(signal.SIGINT, remove_setup)

    ct_ip = ct.c_ubyte * 16
    bpf_aggreg["sids"][0] = ct_ip.from_buffer_copy(L1.sid_up_bytes)
    bpf_aggreg["sids"][1] = ct_ip.from_buffer_copy(L2.sid_up_bytes)
    bpf_aggreg["sids"][2] = ct_ip.from_buffer_copy(socket.inet_pton(socket.AF_INET6, sid_cpe))
    bpf_aggreg["weights"][0] = ct.c_int(L1.weight)
    bpf_aggreg["weights"][1] = ct.c_int(L2.weight)
    bpf_aggreg["wrr"][0] = ct.c_int(-1)
    bpf_aggreg["wrr"][1] = ct.c_int(0)
    bpf_aggreg["wrr"][2] = ct.c_int(math.gcd(L1.weight, L2.weight))

    bpf_dm["dm_messages"].open_perf_buffer(handle_dm_reply)

    probes_sender = ProbesSender()
    probes_sender.start()

    try:
        while 1:
            bpf_dm.kprobe_poll()

    except DaemonShutdown:
        kill_daemon(probes_sender)

def kill_daemon(probes_sender):
    probes_sender.shutdown_flag.set()
    L1.remove_tc() # TODO fail
    L2.remove_tc()

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=ifaces_down[0])[0]
    ipr.route("del", dst=prefix, oif=idx)
    ipr.route("del", dst=sid_otp_down + '/128', oif=idx)

    sys.exit(0)

@log_traceback
def get_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    fh = logging.FileHandler("/tmp/link_aggreg_{}.log".format(rt_name), "a")
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    formatter = logging.Formatter("%(asctime)s: %(message)s",
                                                  "%b %e %H:%M:%S")
    fh.setFormatter(formatter)
    return logger, fh.stream.fileno()

if __name__ == '__main__':
    if len(sys.argv) < 10:
        print("Format: ./link_aggreg.py PREFIX SID-CPE SID1-UP SID1-DOWN WEIGHT1 SID2-UP SID2-DOWN WEIGHT2 SID-OTP-UP SID-OTP-DOWN DEV-DOWN1,DEV-DOWN2,... DEV-UP1,DEV-UP2,...")
        sys.exit(1)

    prefix, sid_cpe, sid1_up, sid1_down, w1, sid2_up, sid2_down, w2, sid_otp_up, sid_otp_down, ifaces_down, ifaces_up = sys.argv[1:]
    ifaces_down = ifaces_down.split(',')
    ifaces_up = ifaces_up.split(',')
    L1 = Link(sid1_down, sid1_up, w1)
    L2 = Link(sid2_down, sid2_up, w2)
    sid_otp_down_bytes = socket.inet_pton(socket.AF_INET6, sid_otp_down)
    sid_otp_up_bytes = socket.inet_pton(socket.AF_INET6, sid_otp_up)
    
    bpf_aggreg, fds_aggreg = install_rt(prefix, 'link_aggreg_bpf.c', 'LB', ('sids', 'weights', 'wrr'))
    rt_name = prefix.replace('/','-')

    bpf_dm, fds_dm = install_rt(sid_otp_down + '/128', 'dm_recv_bpf.c', 'DM_recv', ('dm_messages',))
    
    logger, fd_logger = get_logger()

    keep_fds = [fd_logger] + fds_aggreg + fds_dm
    daemon = Daemonize(app="link_aggreg", pid=PID.format(rt_name), action=lambda: run_daemon(bpf_aggreg, bpf_dm),
            keep_fds=keep_fds, logger=logger)

    print("Link aggregation daemon forked to background.")
    daemon.start()
