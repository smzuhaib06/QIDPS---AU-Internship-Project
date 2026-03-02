import time
from collections import defaultdict

# Sliding window memory (lightweight)
SRC_STATE = defaultdict(lambda: {
    "ports": set(),
    "hosts": set(),
    "last_times": [],
    "dns_count": 0,
    "http_count": 0
})

WINDOW = 10          # seconds
LOW_SLOW_WINDOW = 60 # seconds

def cleanup(times, now, window):
    return [t for t in times if now - t <= window]


def detect_scan(src, dst, dport, ts):
    state = SRC_STATE[src]
    state["ports"].add(dport)
    state["hosts"].add(dst)
    state["last_times"].append(ts)
    state["last_times"] = cleanup(state["last_times"], ts, WINDOW)

    if len(state["ports"]) >= 10 and len(state["last_times"]) >= 10:
        return True
    return False


def detect_horizontal_scan(src):
    return len(SRC_STATE[src]["hosts"]) >= 10


def detect_udp_flood(features):
    return (
        features["pkt_rate"] > 500 and
        features["pkt_size_entropy"] < 1.0
    )


def detect_http_flood(dport, features):
    return (
        dport in {80, 443, 8080} and
        features["pkt_rate"] > 50
    )


def detect_dns_abuse(dport, features):
    return (
        dport == 53 and
        features["pkt_rate"] > 100
    )


def detect_beaconing(features):
    return (
        features["var_inter_arrival"] < 0.001 and
        features["pkt_size_entropy"] < 1.5
    )


def detect_low_slow(src, ts):
    state = SRC_STATE[src]
    state["last_times"].append(ts)
    state["last_times"] = cleanup(state["last_times"], ts, LOW_SLOW_WINDOW)

    return 5 <= len(state["last_times"]) <= 10
