class Metrics:
    def __init__(self):
        self.tp = 0  # True Positives
        self.fp = 0  # False Positives
        self.fn = 0  # False Negatives
        self.tn = 0  # True Negatives

    def update(self, true_label, predicted_label):
        """
        Update confusion matrix counters.
        true_label and predicted_label must be:
        - "ATTACK"
        - "NORMAL"
        """

        if true_label == "ATTACK" and predicted_label == "ATTACK":
            self.tp += 1

        elif true_label == "NORMAL" and predicted_label == "ATTACK":
            self.fp += 1

        elif true_label == "ATTACK" and predicted_label == "NORMAL":
            self.fn += 1

        elif true_label == "NORMAL" and predicted_label == "NORMAL":
            self.tn += 1

    def report(self):
        """
        Print evaluation metrics.
        Safe against empty datasets.
        """

        total = self.tp + self.fp + self.fn + self.tn

        print("\n=== DATASET EVALUATION RESULTS ===")
        print(f"Total Samples      : {total}")
        print(f"True Positives     : {self.tp}")
        print(f"False Positives    : {self.fp}")
        print(f"False Negatives    : {self.fn}")
        print(f"True Negatives     : {self.tn}")

        if total == 0:
            print("[WARN] No samples were processed. Check dataset mapping.")
            return

        accuracy = (self.tp + self.tn) / total
        detection_rate = self.tp / max(1, self.tp + self.fn)
        false_positive_rate = self.fp / max(1, self.fp + self.tn)

        print(f"Accuracy           : {accuracy:.4f}")
        print(f"Detection Rate     : {detection_rate:.4f}")
        print(f"False Positive Rate: {false_positive_rate:.4f}")
