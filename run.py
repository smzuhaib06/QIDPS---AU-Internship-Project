from capture.packet_sniffer import start
from utils.logger import get_logger

logger = get_logger("QIDPS")

if __name__ == "__main__":
    logger.info("Q-IDPS starting (packet capture + features)")
    start()
