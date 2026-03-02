from response.firewall import temp_block
from utils.logger import get_logger

logger = get_logger("RESPONSE")

def respond(attacker_ip, attack_type, confidence):
    if confidence < 0.7:
        return  # Avoid aggressive action on weak signals

    if attack_type in ["SCAN", "BRUTEFORCE", "C2"]:
        logger.warning(
            f"ALERT src={attacker_ip} type={attack_type} confidence={confidence}"
        )
        temp_block(attacker_ip)
    if attack_type == "PERMANENT_BLOCK":
    	temp_block(attacker_ip)   # or permanent block logic
    	logger.critical(f"PERMANENT BLOCK applied to {attacker_ip}")
    	return


    elif attack_type == "DOS":
        logger.warning(
            f"DOS detected from {attacker_ip}, blocking immediately"
        )
        temp_block(attacker_ip)
