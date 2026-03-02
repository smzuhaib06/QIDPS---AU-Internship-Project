import numpy as np

# Predefined attack state (learned offline)
ATTACK_TEMPLATE = np.array([0.9, 0.8, 0.7, 0.6])

def quantum_similarity(encoded_angles):
    """
    Simulate quantum state overlap
    """

    overlap = np.dot(encoded_angles, ATTACK_TEMPLATE)
    score = abs(overlap) / np.linalg.norm(ATTACK_TEMPLATE)

    return score
