from collections import defaultdict
from core.config import FLOW_TIMEOUT

class Flow:
    def __init__(self, ts):
        self.start_ts = ts
        self.last_ts = ts

        self.packets = 0
        self.bytes = 0

        self.sizes = []
        self.inter_arrivals = []

        self.last_pkt_ts = None
        self.tcp_flags = defaultdict(int)

        self.in_pkts = 0
        self.out_pkts = 0

flows = {}

def flow_key(src, dst, sport, dport, proto):
    return (src, dst, sport, dport, proto)

def update_flow(key, pkt_size, ts, flags, direction):
    if key not in flows:
        flows[key] = Flow(ts)

    f = flows[key]

    f.packets += 1
    f.bytes += pkt_size
    f.sizes.append(pkt_size)

    if f.last_pkt_ts is not None:
        f.inter_arrivals.append(ts - f.last_pkt_ts)

    f.last_pkt_ts = ts
    f.last_ts = ts

    if flags:
        f.tcp_flags[flags] += 1

    if direction == "in":
        f.in_pkts += 1
    else:
        f.out_pkts += 1

def get_expired_flows(current_ts):
    expired = []
    for k, f in flows.items():
        if current_ts - f.last_ts > FLOW_TIMEOUT:
            expired.append(k)
    return expired
