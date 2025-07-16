import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=44818, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x65\x00\x04\x00\x00\x00\x00\x00'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"EtherNet/IP detected on {target}:44818")
            return True
    except Exception as e:
        logger.debug(f"EtherNet/IP scan error: {e}")
    finally:
        sock.close()
    return False
