import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=2155, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x00'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"Interbus detected on {target}:2155")
            return True
    except Exception as e:
        logger.debug(f"Interbus scan error: {e}")
    finally:
        sock.close()
    return False
