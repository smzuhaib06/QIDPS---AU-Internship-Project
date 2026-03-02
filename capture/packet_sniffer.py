from scapy.all import sniff, IP, TCP, UDP
from core.pipeline import process_packet
from core.config import INTERFACE
from utils.logger import get_logger

logger = get_logger("SNIFFER")
#direction = (
#    "out" if pkt[IP].src.startswith("192.168.50.")
#    else "in"
#)

def on_packet(pkt):
    if IP not in pkt:
        return

    proto = None
    src_port = dst_port = 0
    flags = 0

    if TCP in pkt:
        proto = 6
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = int(pkt[TCP].flags)
    elif UDP in pkt:
        proto = 17
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    else:
        return
	
    direction = (	
	"out" if pkt[IP].src.startswith("192.168.50.")
	else "in"
    )
    process_packet({
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "pkt_size": len(pkt),
        "tcp_flags": flags,
        "timestamp": pkt.time,
        "direction": direction
    })

def start():
    logger.info(f"Starting packet capture on {INTERFACE}")
    sniff(
        iface=INTERFACE,
        prn=on_packet,
        store=False
    )
