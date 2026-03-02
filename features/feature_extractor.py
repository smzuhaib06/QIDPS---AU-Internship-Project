import numpy as np
from features.entropy import shannon_entropy

def compute_features(flow):
    duration = max(flow.last_ts - flow.start_ts, 1e-6)

    pkt_rate = flow.packets / duration
    byte_rate = flow.bytes / duration

    sizes = np.array(flow.sizes)
    inter = np.array(flow.inter_arrivals) if flow.inter_arrivals else np.array([0.0])

    features = {
        "pkt_rate": pkt_rate,
        "byte_rate": byte_rate,
        "mean_pkt_size": float(sizes.mean()),
        "var_pkt_size": float(sizes.var()),
        "mean_inter_arrival": float(inter.mean()),
        "var_inter_arrival": float(inter.var()),
        "pkt_size_entropy": shannon_entropy(sizes),
        "direction_ratio": flow.in_pkts / max(1, flow.out_pkts),
        "flow_duration": duration
    }

    return features
