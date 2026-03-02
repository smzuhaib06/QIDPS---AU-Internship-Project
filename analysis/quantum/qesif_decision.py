#from .qesif_encoder import quantum_encode
#from .quantum_similarity import quantum_similarity

#def quantum_classify(features, threshold=0.7):
#    angles = quantum_encode(features)
#    score = quantum_similarity(angles)

#    if score >= threshold:
#        return "ATTACK", score
#    return "NORMAL", score
"""
QESIF-Inspired Quantum Decision Module (Offline)

This module simulates quantum disturbance-based intrusion
decision logic inspired by QESIF, without real quantum hardware.

It operates on extracted flow features and produces:
- decision: ATTACK | NORMAL
- quantum_score: float (0.0 - 1.0)
"""

import math


# ============================================================
# QUANTUM DISTURBANCE MODEL
# ============================================================

def _quantum_disturbance(features):
    """
    Simulate quantum disturbance caused by abnormal traffic.

    Higher disturbance => higher probability of attack.
    """

    pkt_rate = features.get("pkt_rate", 0.0)
    entropy = features.get("pkt_size_entropy", 0.0)
    duration = features.get("flow_duration", 0.0)
    direction_ratio = features.get("direction_ratio", 0.0)

    # Normalize components (QESIF-style abstractions)
    rate_term = min(pkt_rate / 1000.0, 1.0)
    entropy_term = min(entropy / 5.0, 1.0)
    time_term = math.exp(-duration)   # short bursts → high disturbance
    asymmetry_term = min(abs(direction_ratio - 1.0), 1.0)

    # Weighted disturbance (heuristic, explainable)
    disturbance = (
        0.35 * rate_term +
        0.25 * entropy_term +
        0.20 * time_term +
        0.20 * asymmetry_term
    )

    return min(disturbance, 1.0)


# ============================================================
# QUANTUM MEASUREMENT & DECISION
# ============================================================

def quantum_classify(features):
    """
    Quantum-inspired classification (QESIF-style).

    Returns:
        decision       -> "ATTACK" | "NORMAL"
        quantum_score  -> float [0.0 - 1.0]
    """

    # Step 1: Compute disturbance
    disturbance = _quantum_disturbance(features)

    # Step 2: Convert disturbance to measurement probability
    # (analogous to quantum measurement collapse)
    quantum_score = disturbance

    # Step 3: Threshold-based decision (QESIF-style)
    # NOTE: QESIF thresholds are empirical & simulation-based
    if quantum_score >= 0.6:
        decision = "ATTACK"
    else:
        decision = "NORMAL"

    return decision, quantum_score
