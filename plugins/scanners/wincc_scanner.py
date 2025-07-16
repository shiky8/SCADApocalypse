import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=4800, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        logger.info(f"Siemens WinCC service detected on {target}:{port}")
        return True
    except Exception as e:
        logger.debug(f"WinCC scan error: {e}")
        return False
    finally:
        sock.close()
