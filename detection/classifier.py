from utils.time_utils import now
from detection.rules import classify_attack

# -----------------------------
# CLASSIFIER CONFIG
# -----------------------------
PKT_RATE_HIGH = 100
PKT_RATE_VERY_HIGH = 500

SHORT_FLOW = 2.0        # seconds
VERY_SHORT_FLOW = 0.2

LOW_ENTROPY = 1.2
VERY_LOW_ENTROPY = 0.8


def classify_flow(flow_key, features):
    """
    Flow-level attack classification.

    Returns:
        decision     -> NORMAL | ATTACK
        attack_type  -> NORMAL | SCAN | BRUTEFORCE | DOS | UDP_FLOOD |
                        HTTP_FLOOD | DNS_ABUSE | C2_BEACON | LOW_SLOW
        confidence   -> float [0.0 - 1.0]
    """

    src, dst, sport, dport, proto = flow_key

    pkt_rate = features["pkt_rate"]
    duration = features["flow_duration"]
    entropy = features["pkt_size_entropy"]
    var_iat = features["var_inter_arrival"]

    # --------------------------------------------------
    # 1. RULE-BASED BASE CLASSIFICATION (Existing Logic)
    # --------------------------------------------------
    attack_type = classify_attack(features, flow_key)

    # --------------------------------------------------
    # 2. EXTENDED ATTACK TYPE REFINEMENT
    # --------------------------------------------------

    # --- UDP FLOOD ---
    if proto == 17 and pkt_rate > PKT_RATE_VERY_HIGH and entropy < LOW_ENTROPY:
        attack_type = "UDP_FLOOD"

    # --- HTTP FLOOD ---
    if dport in {80, 443, 8080} and pkt_rate > PKT_RATE_HIGH:
        attack_type = "HTTP_FLOOD"

    # --- DNS ABUSE ---
    if dport == 53 and pkt_rate > PKT_RATE_HIGH:
        attack_type = "DNS_ABUSE"

    # --- C2 BEACONING ---
    if var_iat < 0.001 and entropy < LOW_ENTROPY:
        attack_type = "C2_BEACON"

    # --- LOW AND SLOW PROBING ---
    if VERY_SHORT_FLOW < duration < 10 and pkt_rate < 10 and entropy < VERY_LOW_ENTROPY:
        attack_type = "LOW_SLOW"

    # --------------------------------------------------
    # 3. NORMAL TRAFFIC
    # --------------------------------------------------
    if attack_type == "NORMAL":
        return "NORMAL", "NORMAL", 0.0

    # --------------------------------------------------
    # 4. CONFIDENCE CALCULATION (EXPLAINABLE)
    # --------------------------------------------------
    confidence = 0.4

    # Packet rate contribution
    if pkt_rate > PKT_RATE_HIGH:
        confidence += 0.2

    if pkt_rate > PKT_RATE_VERY_HIGH:
        confidence += 0.2

    # Duration contribution
    if duration < SHORT_FLOW:
        confidence += 0.1

    if duration < VERY_SHORT_FLOW:
        confidence += 0.1

    # Entropy contribution
    if entropy < LOW_ENTROPY:
        confidence += 0.1

    confidence = min(confidence, 1.0)

    return "ATTACK", attack_type, confidence
