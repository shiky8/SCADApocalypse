import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=2404, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x68\x04\x07\x00\x00\x00'
        sock.send(request)
        response = sock.recv(1024)
        if b'\x68' in response:
            logger.info(f"IEC 60870-5-104 detected on {target}:2404")
            return True
    except Exception as e:
        logger.debug(f"IEC 60870-5-104 scan error: {e}")
    finally:
        sock.close()
    return False
