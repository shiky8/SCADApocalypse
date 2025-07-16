import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=47808, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x81\x0a\x00\x0a\x01\x20\xff\xff\x00\x00'
        sock.send(request)
        response = sock.recv(1024)
        if b'\x81\x0a' in response:
            logger.info(f"BACnet/IP detected on {target}:47808")
            return True
    except Exception as e:
        logger.debug(f"BACnet/IP scan error: {e}")
    finally:
        sock.close()
    return False
