import json

def load_quantum_metrics(path="quantum_results.json"):
    with open(path, "r") as f:
        q = json.load(f)

    fidelity = q["fidelity"]
    error_score = (q["x_error"] + q["y_error"] + q["z_error"]) / 3

    return {
        "fidelity": fidelity,
        "error_score": error_score
    }


def quantum_risk_multiplier(fidelity):
    """
    Lower fidelity → higher risk
    """
    if fidelity >= 0.9:
        return 0.8
    elif fidelity >= 0.75:
        return 1.0
    elif fidelity >= 0.6:
        return 1.2
    else:
        return 1.5
