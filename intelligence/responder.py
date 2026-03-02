import subprocess
from utils.logger import get_logger

logger = get_logger("RESPONSE")

BLOCKING_ENABLED = False  # examiner-safe
alert_logger = get_logger("ALERT")



def respond(flow_key, attack_type, confidence):
    src_ip = flow_key[0]

    if confidence < 0.6:
        return

    logger.warning(
        f"ALERT src={src_ip} type={attack_type} confidence={confidence:.2f}"
    )
    alert_logger.warning(
    f"ALERT src={src_ip} type={attack_type} confidence={confidence:.2f}"
    )
    if BLOCKING_ENABLED and confidence > 0.85:
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
                check=True
            )
            logger.critical(f"BLOCKED {src_ip}")
        except Exception as e:
            logger.error(f"Block failed: {e}")
