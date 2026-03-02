import subprocess
import time
from utils.logger import get_logger

logger = get_logger("FIREWALL")

BLOCK_DURATION = 60  # seconds

def block_ip(ip):
    if not isinstance(ip, str):
        logger.error(f"Invalid IP passed to firewall: {ip}")
        return

    check_cmd = ["iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP"]
    exists = subprocess.run(
        check_cmd,
        stderr=subprocess.DEVNULL
    ).returncode == 0

    if not exists:
        cmd = ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True)
        logger.warning(f"Blocked IP {ip}")

def unblock_ip(ip):
    cmd = ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd, stderr=subprocess.DEVNULL)

def temp_block(ip):
    block_ip(ip)
    time.sleep(BLOCK_DURATION)
    unblock_ip(ip)
    logger.info(f"Unblocked IP {ip}")
