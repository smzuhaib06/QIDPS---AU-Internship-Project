import math
from collections import defaultdict

# Number of flows used to learn baseline
BASELINE_SIZE = 50

# Z-score threshold for anomaly
Z_THRESHOLD = 3.0

# Number of violated features required to flag attack
MIN_VIOLATIONS = 2


class BinaryIDS:
    def __init__(self):
        self.baseline = defaultdict(list)
        self.stats = {}
        self.ready = False

        self.selected_features = [
            "pkt_rate",
            "byte_rate",
            "mean_inter_arrival",
            "pkt_size_entropy",
            "flow_duration",
            "direction_ratio"
        ]

    def update_baseline(self, features):
        for f in self.selected_features:
            if f in features:
                self.baseline[f].append(features[f])

        # Check if baseline is complete
        if len(self.baseline[self.selected_features[0]]) >= BASELINE_SIZE:
            self._compute_stats()
            self.ready = True

    def _compute_stats(self):
        for f, values in self.baseline.items():
            mean = sum(values) / len(values)
            var = sum((x - mean) ** 2 for x in values) / len(values)
            std = math.sqrt(var) + 1e-6
            self.stats[f] = (mean, std)

    def classify(self, features):
        # Learning phase
        if not self.ready:
            self.update_baseline(features)
            return "LEARNING"

        violations = 0
        reasons = []

        for f, (mean, std) in self.stats.items():
            if f not in features:
                continue

            z = abs(features[f] - mean) / std
            if z > Z_THRESHOLD:
                violations += 1
                reasons.append(f"{f}: z={z:.2f}")

        if violations >= MIN_VIOLATIONS:
            return "ATTACK"
        else:
            return "NORMAL"
