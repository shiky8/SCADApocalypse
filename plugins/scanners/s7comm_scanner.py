import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=102, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02'
        sock.send(request)
        response = sock.recv(1024)
        if b'\x03\x00' in response:
            logger.info(f"S7Comm detected on {target}:102")
            return True
    except Exception as e:
        logger.debug(f"S7Comm scan error: {e}")
    finally:
        sock.close()
    return False
