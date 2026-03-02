import time
from collections import defaultdict

# -----------------------------
# CONFIGURATION
# -----------------------------
RISK_DECAY_WINDOW = 300     # seconds (5 min)
TEMP_BLOCK_THRESHOLD = 3
PERM_BLOCK_THRESHOLD = 7

ATTACK_WEIGHTS = {
    "SCAN": 1,
    "BRUTEFORCE": 3,
    "DOS": 5
}

# -----------------------------
# STATE
# -----------------------------
_risk_table = defaultdict(list)


def update_risk(src_ip, attack_type):
    """
    Update cumulative risk score for a source IP.
    """
    now_ts = time.time()
    weight = ATTACK_WEIGHTS.get(attack_type, 1)

    _risk_table[src_ip].append((now_ts, weight))

    _prune_old(src_ip)

    return compute_risk(src_ip)


def compute_risk(src_ip):
    """
    Compute total risk score for an IP.
    """
    return sum(weight for _, weight in _risk_table[src_ip])


def _prune_old(src_ip):
    """
    Remove expired risk entries.
    """
    now_ts = time.time()
    _risk_table[src_ip] = [
        (ts, w) for ts, w in _risk_table[src_ip]
        if now_ts - ts <= RISK_DECAY_WINDOW
    ]
