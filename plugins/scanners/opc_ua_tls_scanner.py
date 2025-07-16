import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=4843, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x16\x03\x01\x00\x2e'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"OPC UA TLS detected on {target}:4843")
            return True
    except Exception as e:
        logger.debug(f"OPC UA TLS scan error: {e}")
    finally:
        sock.close()
    return False
