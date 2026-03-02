from utils.time_utils import now
from utils.logger import get_logger

from intelligence.tracker import update_tracker, track_ssh_attempt
from intelligence.risk_engine import update_risk
from capture.flow_table import (
    flows,
    flow_key,
    update_flow,
    get_expired_flows
)

from features.feature_extractor import compute_features
from detection.classifier import classify_flow
from intelligence.scorer import score_attack
from response.responder import respond


logger = get_logger("PIPELINE")

# -----------------------------
# SAFETY / STABILITY CONSTANTS
# -----------------------------
MIN_PACKETS = 3
MIN_DURATION = 0.05  # seconds

PROTECTED_IPS = {"192.168.50.1"}          # gateway IP
WHITELIST_PORTS = {53, 123, 67, 68}        # DNS, NTP, DHCP

SSH_BRUTE_THRESHOLD = 5
SSH_BRUTE_CONFIDENCE = 0.85


def process_packet(pkt):
    """
    Main pipeline entry point.
    """

    # -----------------------------
    # 1. Build canonical flow key
    # -----------------------------
    key = flow_key(
        pkt["src_ip"],
        pkt["dst_ip"],
        pkt["src_port"],
        pkt["dst_port"],
        pkt["protocol"]
    )

    # -----------------------------
    # 2. Update flow state
    # -----------------------------
    update_flow(
        key=key,
        pkt_size=pkt["pkt_size"],
        ts=pkt["timestamp"],
        flags=pkt["tcp_flags"],
        direction=pkt["direction"]
    )

    # -----------------------------
    # 3. Expire completed flows
    # -----------------------------
    expired = get_expired_flows(now())

    for k in expired:
        flow = flows.pop(k)

        duration = flow.last_ts - flow.start_ts
        src_ip, dst_ip, sport, dport, proto = k

        # -----------------------------
        # 4. FLOW VALIDITY GATES
        # -----------------------------
        if flow.packets < MIN_PACKETS:
            continue

        if duration < MIN_DURATION:
            continue

        # -----------------------------
        # 5. WHITELIST INFRA TRAFFIC
        # -----------------------------
        if sport in WHITELIST_PORTS or dport in WHITELIST_PORTS:
            features = compute_features(flow)
            _log_flow(k, "NORMAL", "NORMAL", 0.0, features)
            continue

        # -----------------------------
        # 6. SSH BRUTE-FORCE (SERVICE LEVEL)
        # -----------------------------
        if dport == 22:
            attempts = track_ssh_attempt(src_ip)

            if attempts >= SSH_BRUTE_THRESHOLD:
                if src_ip not in PROTECTED_IPS:
                    respond(src_ip, "BRUTEFORCE", SSH_BRUTE_CONFIDENCE)

                _log_flow(
                    k,
                    "ATTACK",
                    "BRUTEFORCE",
                    SSH_BRUTE_CONFIDENCE,
                    {}
                )
                continue

        # -----------------------------
        # 7. DIRECTION INFERENCE
        # -----------------------------
        if flow.out_pkts < flow.in_pkts:
            continue

        # -----------------------------
        # 8. FEATURE EXTRACTION
        # -----------------------------
        features = compute_features(flow)

        # -----------------------------
        # 9. FLOW-LEVEL DETECTION
        # -----------------------------
        decision, attack_type, base_conf = classify_flow(k, features)
        confidence = base_conf

        # -----------------------------
        # 10. INTELLIGENCE & RESPONSE
        # -----------------------------
        if decision == "ATTACK":
            tracker_state = update_tracker(k, attack_type)
            confidence = score_attack(features, tracker_state)

            if src_ip in PROTECTED_IPS:
                logger.warning(
                    f"Attempted block on protected IP {src_ip} — ignored"
                )
                decision = "NORMAL"
                attack_type = "NORMAL"
            confidence = 0.0                #respond(src_ip, attack_type, confidence)
        else:
        # --------------------------------
        # Risk aggregation (Del-5)
        # --------------------------------
            risk_score = update_risk(src_ip, attack_type)

            logger.warning(
                f"RISK UPDATE src={src_ip} "
                f"attack={attack_type} "
                f"risk={risk_score}"
            )

        # --------------------------------
        # Escalation logic
        # --------------------------------
            if risk_score >= 7:
                    respond(src_ip, "PERMANENT_BLOCK", 1.0)

            elif risk_score >= 3:
                    respond(src_ip, attack_type, confidence)
        # -----------------------------
        # 11. FINAL LOGGING
        # -----------------------------
        _log_flow(k, decision, attack_type, confidence, features)


# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def _log_flow(flow_key, decision, attack_type, confidence, features):
    logger.info(
        f"FLOW={flow_key} "
        f"DECISION={decision} "
        f"TYPE={attack_type} "
        f"CONF={confidence:.2f} "
        f"FEATURES={features}"
    )
