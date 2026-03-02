def score_attack(features, tracker_state):
    score = 0.0

    # Feature-based confidence
    if features["pkt_rate"] > 100:
        score += 0.3
    if features["var_inter_arrival"] < 0.01:
        score += 0.3
    if features["pkt_size_entropy"] < 2:
        score += 0.2

    # Temporal confidence
    if tracker_state["count"] > 5:
        score += 0.4
    if len(tracker_state["types"]) > 1:
        score += 0.3

    return min(score, 1.0)
