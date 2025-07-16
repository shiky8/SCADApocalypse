import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=502, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x00\x01\x00\x00\x00\x06\x01\x2b\x0e\x01\x00'
        sock.send(request)
        response = sock.recv(1024)
        if b'\x2b\x0e' in response:
            logger.info(f"Modbus TCP detected on {target}:502")
            return True
    except Exception as e:
        logger.debug(f"Modbus TCP scan error: {e}")
    finally:
        sock.close()
    return False
