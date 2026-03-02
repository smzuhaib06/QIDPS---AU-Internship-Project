import numpy as np

def shannon_entropy(values):
    if len(values) == 0:
        return 0.0

    values = np.array(values)
    probs = values / values.sum()

    probs = probs[probs > 0]
    return -float((probs * np.log2(probs)).sum())
