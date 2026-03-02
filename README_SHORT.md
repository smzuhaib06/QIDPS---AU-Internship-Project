# Q‑IDPS (Quick Overview)

A lightweight intrusion detection/prevention gateway tailored for IoT subnets.  It
captures traffic, builds flows, computes simple statistical features, and classifies
behaviour using both rule‑based logic and a z‑score anomaly detector.

## Key Components

* **capture/** – packet sniffer and flow table
* **core/** – configuration, flow pipeline, and a binary anomaly IDS
* **detection/** – feature‑based classifier and rule definitions
* **features/** – rate, entropy and timing extractors
* **intelligence/** – scoring, risk tracking, SSH brute detection
* **response/** – iptables wrapper for blocking
* **utils/** – logging and timing helpers
* **run.py** – entry point; `service/qidps.service` for systemd

## Quick start

```bash
git clone <repo>
cd Q_IDPS
pip install -r req.txt          # requires python3
sudo python run.py              # or install the systemd service
```

Edit `core/config.py` to set your interface/subnet.  Run as root to capture packets
and manage iptables.

## Design notes

* Flows expire after a few seconds; only those with ≥3 packets and >0.05 s are
  analysed.
* Features include packet/byte rates, entropy, duration, and direction ratio.
* Baseline of 50 flows is learned; anomalies are flagged when ≥2 features exceed a
  z‑score of 3.
* SSH brute forcing and high‑risk sources trigger immediate blocking.

## License & contact

MIT-style; see LICENSE file.  Report issues via the repository's GitHub page.
