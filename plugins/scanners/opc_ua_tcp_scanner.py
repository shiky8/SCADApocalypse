import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=4840, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'HELLO'
        sock.send(request)
        response = sock.recv(1024)
        if response.startswith(b'ACK'):
            logger.info(f"OPC UA TCP detected on {target}:4840")
            return True
    except Exception as e:
        logger.debug(f"OPC UA TCP scan error: {e}")
    finally:
        sock.close()
    return False
