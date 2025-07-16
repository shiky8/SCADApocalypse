import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=1089, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x00'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"Foundation Fieldbus HSE detected on {target}:1089")
            return True
    except Exception as e:
        logger.debug(f"Foundation Fieldbus HSE scan error: {e}")
    finally:
        sock.close()
    return False
