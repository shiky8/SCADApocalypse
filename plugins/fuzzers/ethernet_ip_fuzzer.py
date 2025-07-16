
from utils.payload_loader import load_payloads
from utils.logger import setup_logger
import socket
import binascii

logger = setup_logger()

def fuzz(target, port=44818, payloads_file='ethernet_ip_payloads.txt', iterations=100):
    payloads = load_payloads(payloads_file)
    if not payloads:
        logger.error("No EtherNet/IP payloads loaded")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, port))
        logger.info(f"Connected to EtherNet/IP on {target}:{port}")
        for i in range(min(iterations, len(payloads))):
            payload_hex = payloads[i]
            payload = binascii.unhexlify(payload_hex)
            logger.info(f"Trying EtherNet/IP {payload = }")
            sock.send(payload)
            try:
                response = sock.recv(1024)
                logger.info(f"Fuzz iteration {i+1}: Received {len(response)} bytes")
            except socket.timeout:
                logger.warning(f"Fuzz iteration {i+1}: No response (timeout)")
    except Exception as e:
        logger.error(f"EtherNet/IP fuzzing error: {e}")
    finally:
        sock.close()
