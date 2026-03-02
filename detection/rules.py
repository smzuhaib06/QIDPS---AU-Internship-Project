def classify_attack(features, flow_key):
    src, dst, sport, dport, proto = flow_key

    pkt_rate = features["pkt_rate"]
    duration = features["flow_duration"]
    entropy = features["pkt_size_entropy"]
    inter_var = features["var_inter_arrival"]
    dir_ratio = features["direction_ratio"]

    # ---- NORMAL ----
    if pkt_rate < 50 and entropy < 8 and duration < 10:
        return "NORMAL"

    # ---- SCAN ----
    # Short flows, moderate rate, repeated attempts
    if duration < 2 and pkt_rate > 30 and entropy < 6:
        return "SCAN"

    # ---- BRUTEFORCE ----
    # SSH authentication abuse
    if dport == 22 or sport == 22:
        if pkt_rate > 50 and inter_var < 0.02:
            return "BRUTEFORCE"

    # ---- DOS ----
    # Flooding behavior
    if pkt_rate > 300 and inter_var < 0.01:
        return "DOS"

    # ---- C2 / BEACONING ----
    # Low-rate periodic long-lived flows
    if pkt_rate < 5 and duration > 30 and inter_var < 0.1:
        return "C2"

    return "NORMAL"
