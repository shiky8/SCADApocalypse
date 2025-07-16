import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=20000, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x05\x64\x01\xc4\x01'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"DNP3 detected on {target}:20000")
            return True
    except Exception as e:
        logger.debug(f"DNP3 scan error: {e}")
    finally:
        sock.close()
    return False
