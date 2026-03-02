from collections import defaultdict, deque
import time

# src_ip -> attack stats
attack_state = defaultdict(lambda: {
    "count": 0,
    "types": set(),
    "last_seen": 0
})

WINDOW = 60  # seconds

def update_tracker(flow_key, attack_type):
    src_ip = flow_key[0]
    now = time.time()

    state = attack_state[src_ip]

    # reset if time window expired
    if now - state["last_seen"] > WINDOW:
        state["count"] = 0
        state["types"].clear()

    state["count"] += 1
    state["types"].add(attack_type)
    state["last_seen"] = now

    return state

# SSH brute-force tracking
SSH_WINDOW = 60        # seconds
SSH_THRESHOLD = 10     # attempts

_ssh_attempts = defaultdict(deque)


def track_ssh_attempt(src_ip):
    """
    Track SSH connection attempts per source IP.
    """
    now_ts = time.time()
    q = _ssh_attempts[src_ip]

    q.append(now_ts)

    # Remove old attempts
    while q and now_ts - q[0] > SSH_WINDOW:
        q.popleft()

    return len(q)
