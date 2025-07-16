import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=4319, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'fox'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"Fox Protocol detected on {target}:4319")
            return True
    except Exception as e:
        logger.debug(f"Fox Protocol scan error: {e}")
    finally:
        sock.close()
    return False
