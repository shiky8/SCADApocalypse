import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=135, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x05\x00\x0b\x03\x10'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"OPC Classic detected on {target}:135")
            return True
    except Exception as e:
        logger.debug(f"OPC Classic scan error: {e}")
    finally:
        sock.close()
    return False
