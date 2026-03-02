import numpy as np

def quantum_encode(features):
    """
    QESIF-style angle encoding
    """

    vec = np.array([
        features["pkt_rate"],
        features["byte_rate"],
        features["mean_pkt_size"],
        features["pkt_size_entropy"]
    ], dtype=float)

    norm = np.linalg.norm(vec) + 1e-9
    vec = vec / norm

    # Map to quantum angles
    angles = vec * np.pi

    return angles
