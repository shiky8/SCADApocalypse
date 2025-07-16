import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=8883, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x16\x03\x01\x00\x2e'
        sock.send(request)
        response = sock.recv(1024)
        if response:
            logger.info(f"MQTT Secure detected on {target}:8883")
            return True
    except Exception as e:
        logger.debug(f"MQTT Secure scan error: {e}")
    finally:
        sock.close()
    return False
