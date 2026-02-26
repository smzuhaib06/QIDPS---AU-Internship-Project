# Q-IDPS

Real-time gateway intrusion detection and prevention for IoT networks with entropy-based analysis.

## Features

- Packet capture & flow tracking
- Feature extraction (rates, entropy, direction, etc.)
- Z-score anomaly detection and rule-based classification
- Optional iptables blocking and systemd deployment
- Console/file logging

## Structure

```
capture/   # sniffer, flows
core/      # config, pipeline, ids
etection/ # rules, classifier
features/  # feature & entropy functions
intelligence/ # scoring, tracking
response/  # firewall, responder
utils/     # logging, time utils
service/   # qidps.service
run.py     # entry point
req.txt    # deps
```

## Installation

```bash
git clone <repo>
cd Q_IDPS
pip install -r req.txt
```

Configure `core/config.py` for interface and subnet.

## Usage

```bash
sudo python run.py
```

As a service:

```bash
sudo cp service/qidps.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now qidps
```

Logs are written to `q_idps.log`.

## Notes

- Python 3.8+; root required for capture and iptables.
- Entropy is used for anomaly scoring; no quantum hardware is needed.
  - Low entropy: +0.2
  - Repeated attacks (>5 in window): +0.4
  - Multiple attack types detected: +0.3

**tracker.py**
- Tracks attack patterns per source IP in 60-second time windows
- Maintains: attack count, attack types, last seen timestamp
- Resets state when window expires
- Used for temporal correlation of attacks from same source

### response/

**firewall.py**
- Integrates with Linux iptables for IP blocking
- `block_ip(ip)`: Inserts FORWARD DROP rule for source IP
- `unblock_ip(ip)`: Removes blocking rule
- `temp_block(ip)`: Blocks for 300 seconds then unblocks
- Idempotent: checks if rule already exists before insertion

## Installation

### Prerequisites

- Python 3.8+
- Linux system (tested on Debian/Raspberry Pi)
- `root` or `sudo` privileges for packet capture and iptables access
- Network interface in promiscuous mode or dedicated monitoring interface

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Q-IDPS.git
   cd Q-IDPS
   ```

2. **Install dependencies**
   ```bash
   sudo pip install -r req.txt
   ```
   
   Dependencies:
   - `scapy==2.5.0` - Packet manipulation and capture
   - `numpy==1.26.4` - Statistical computations
   - `psutil==5.9.8` - Process and system utilities

3. **Configure system**
   - Edit [core/config.py](core/config.py) to set your network interface and IoT subnet
   - Example: `INTERFACE = "eth0"` for Ethernet interface

## Running the System

### Option 1: Manual Execution

```bash
sudo python3 run.py
```

**Output:**
- Console logs with `[timestamp] LEVEL MODULE: message` format
- Logs are also written to `q_idps.log`
- Detected anomalies logged with features and decision

### Option 2: Background Service (Systemd)

```bash
# Copy service file
sudo cp service/qidps.service /etc/systemd/system/

# Edit service file to match your installation path
sudo nano /etc/systemd/system/qidps.service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable qidps
sudo systemctl start qidps

# Monitor logs
sudo journalctl -u qidps -f
# Or
tail -f q_idps.log
```

## Configuration

Edit [core/config.py](core/config.py) to customize:

```python
INTERFACE = "enp0s8"           # Network interface to monitor
IOT_SUBNET = "192.168.50."     # IoT device subnet prefix
FLOW_TIMEOUT = 5.0             # Flow expiration timeout (seconds)
MIN_FLOW_DURATION = 1.0        # Minimum flow duration to analyze
FEATURE_WINDOW = 5.0           # Feature aggregation window (seconds)
LOG_LEVEL = "INFO"             # Logging level
```

Edit [core/ids.py](core/ids.py) to adjust detection thresholds:

```python
BASELINE_SIZE = 50             # Flows to learn baseline (50)
Z_THRESHOLD = 3.0              # Z-score anomaly threshold (±3σ)
MIN_VIOLATIONS = 2             # Min feature violations to flag
```

## Detected Attack Patterns

The system recognizes:

| Attack Type | Characteristics |
|---|---|
| **SCAN** | Short duration (<2s), moderate packet rate, low entropy |
| **BRUTEFORCE** | SSH traffic (port 22), high rate (>50 pps), very regular timing |
| **DOS** | Extremely high rate (>300 pps), highly regular inter-arrivals (<10ms) |
| **C2/BEACONING** | Low rate (<5 pps), long duration (>30s), very periodic (variance <0.1) |
| **NORMAL** | Low rate, low entropy, short-medium duration |

## Output and Logging

### Log Files

- **q_idps.log** - Complete system log with all decisions and features
- **Console output** - Real-time detection alerts

### Log Format

```
[2026-02-22 14:35:21,456] INFO PIPELINE: FLOW=(('192.168.50.10', '8.8.8.8', 12345, 53, 17)) DECISION=NORMAL TYPE=None CONF=0.00 FEATURES={...}
```

### Log Files Generated

- `q_idps.log` - Primary system log
- `output.txt` - Test output (if applicable)
- `pipe.txt` - Pipeline debug output (if applicable)

## Performance Considerations

- **Memory**: Flow table grows with unique 5-tuples; 5-second timeout keeps memory bounded
- **CPU**: Per-packet processing is O(1); entropy computation is O(n) where n = packet count in flow
- **Throughput**: Suitable for gateway-level traffic (~1000-10000 pps on modern hardware)
- **Latency**: Real-time decision-making, no delayed batch processing

## Quantum-Inspired Approach

This system is **quantum-inspired**, not quantum-hardware dependent:

- Uses **entropy-based modeling** inspired by quantum information theory
- Applies uncertainty quantification principles to network traffic
- Maintains classical implementation for deployment on standard IoT gateways
- Entropy serves as a complementary intelligence layer, not the sole classifier

## Testing & Validation

The system has been designed for testing with:
- Synthetic attack traffic
- Packet capture files
- Live network environments
- Bot-IoT and TON-IoT datasets (configuration-dependent)

## Future Enhancements

- [ ] Deep learning classifier (replacement for Z-score)
- [ ] Distributed detection across multiple gateways
- [ ] Machine learning model export/import
- [ ] Web dashboard for visualization
- [ ] Real-time metric export (Prometheus format)
- [ ] Advanced response actions (rate limiting, packet modification)

## Troubleshooting

### Permission Denied on Packet Capture

```bash
sudo python3 run.py
```

Packet capture requires root privileges.

### No Packets Captured

```bash
# Verify interface exists and is up
ip addr show
sudo ip link set <interface> up

# Check for existing sniffer processes
sudo lsof -i
```

### High False Positive Rate

Increase `Z_THRESHOLD` in [core/ids.py](core/ids.py) or decrease `MIN_VIOLATIONS` after training on your baseline traffic.

### IPS Blocking Not Working

Verify iptables is available:
```bash
sudo iptables -L FORWARD
```

Ensure FORWARD policy allows rules to be inserted.

## License


## Author

SAILAPPAY MOHAMMED ZUHAIB


**Q-IDPS**: Protecting IoT gateways with intelligence and entropy.
