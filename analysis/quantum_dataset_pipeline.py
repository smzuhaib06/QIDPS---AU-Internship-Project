import sys
import os

# ============================================================
# FIX IMPORT PATH (DO NOT TOUCH REAL-TIME CODE)
# ============================================================
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analysis.dataset_loader import load_dataset
from analysis.metrics import Metrics
from detection.classifier import classify_flow


# ============================================================
# QUANTUM (QESIF-INSPIRED) DECISION MODULE
# ============================================================
def quantum_classify(features):
    """
    QESIF-inspired quantum decision logic (offline).

    This DOES NOT simulate qubits directly.
    It emulates quantum disturbance using feature uncertainty,
    similar to QESIF's entropy + fidelity abstraction.

    Returns:
        decision -> ATTACK | NORMAL
        score    -> quantum risk score [0.0 - 1.0]
    """

    # Quantum-inspired observables
    pkt_rate = features["pkt_rate"]
    entropy = features["pkt_size_entropy"]
    duration = features["flow_duration"]

    # ------------------------------------
    # Quantum disturbance estimation
    # ------------------------------------
    disturbance = 0.0

    # High packet rate = higher disturbance
    if pkt_rate > 100:
        disturbance += 0.4
    elif pkt_rate > 50:
        disturbance += 0.25

    # Entropy instability (proxy for superposition collapse)
    if entropy < 1.0 or entropy > 6.0:
        disturbance += 0.3

    # Short-lived bursts (measurement noise)
    if duration < 1.0:
        disturbance += 0.2

    disturbance = min(disturbance, 1.0)

    # ------------------------------------
    # Quantum decision rule
    # ------------------------------------
    if disturbance >= 0.6:
        return "ATTACK", disturbance
    else:
        return "NORMAL", disturbance


# ============================================================
# FEATURE MAPPING FOR BOT-IOT DATASET
# ============================================================
def map_features(row):
    """
    Map Bot-IoT flow fields into GIDPS feature schema.
    Permissive mapping for offline evaluation.
    """

    try:
        duration = float(row["dur"])
    except Exception:
        duration = 0.0
    duration = max(duration, 1e-6)

    try:
        pkts = float(row["pkts"])
    except Exception:
        pkts = 1.0

    try:
        total_bytes = float(row["bytes"])
    except Exception:
        total_bytes = 0.0

    try:
        rate = float(row["rate"])
    except Exception:
        rate = 0.0

    try:
        srate = float(row["srate"])
    except Exception:
        srate = 0.0

    try:
        drate = float(row["drate"])
    except Exception:
        drate = 0.0

    try:
        mean_pkt = float(row["mean"])
    except Exception:
        mean_pkt = 0.0

    try:
        stddev = float(row["stddev"])
    except Exception:
        stddev = 0.0

    features = {
        "pkt_rate": rate,
        "byte_rate": total_bytes / duration,
        "mean_pkt_size": mean_pkt,
        "var_pkt_size": stddev ** 2,
        "mean_inter_arrival": duration / max(pkts, 1),
        "var_inter_arrival": 0.0,
        "pkt_size_entropy": mean_pkt / 100.0,
        "direction_ratio": srate / max(drate, 1e-6),
        "flow_duration": duration
    }

    return features


# ============================================================
# DATASET ANALYSIS PIPELINE (CLASSICAL + QUANTUM)
# ============================================================
def run_dataset_analysis(csv_path):
    df = load_dataset(csv_path)

    classical_metrics = Metrics()
    quantum_metrics = Metrics()

    processed = 0

    for _, row in df.iterrows():

        features = map_features(row)

        # ----------------------------
        # FLOW KEY (BOT-IOT)
        # ----------------------------
        proto_raw = str(row.get("proto", "")).lower()
        if proto_raw == "tcp":
            proto = 6
        elif proto_raw == "udp":
            proto = 17
        else:
            proto = 0

        try:
            sport = int(row.get("sport", 0))
        except Exception:
            sport = 0

        try:
            dport = int(row.get("dport", 0))
        except Exception:
            dport = 0

        flow_key = (
            str(row.get("saddr", "DATASET_SRC")),
            str(row.get("daddr", "DATASET_DST")),
            sport,
            dport,
            proto
        )

        # ----------------------------
        # TRUE LABEL
        # ----------------------------
        try:
            true_label = "ATTACK" if int(row["attack"]) == 1 else "NORMAL"
        except Exception:
            true_label = "NORMAL"

        # ----------------------------
        # CLASSICAL GIDPS
        # ----------------------------
        c_decision, _, _ = classify_flow(flow_key, features)
        if c_decision not in ("ATTACK", "NORMAL"):
            c_decision = "NORMAL"

        classical_metrics.update(true_label, c_decision)

        # ----------------------------
        # QUANTUM (QESIF-INSPIRED)
        # ----------------------------
        q_decision, _ = quantum_classify(features)
        quantum_metrics.update(true_label, q_decision)

        processed += 1

    # ----------------------------
    # REPORT RESULTS
    # ----------------------------
    print(f"\n[INFO] Processed {processed} dataset flows")

    print("\n=== CLASSICAL GIDPS RESULTS ===")
    classical_metrics.report()

    print("\n=== QUANTUM (QESIF-INSPIRED) RESULTS ===")
    quantum_metrics.report()


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="GIDPS Offline Classical vs Quantum Evaluation (Bot-IoT)"
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to Bot-IoT CSV file"
    )

    args = parser.parse_args()

    print("[INFO] Starting classical + quantum dataset analysis...")
    run_dataset_analysis(args.dataset)
