import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=1883, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        request = b'\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x00'
        sock.send(request)
        response = sock.recv(1024)
        if b'\x20' in response:
            logger.info(f"MQTT detected on {target}:1883")
            return True
    except Exception as e:
        logger.debug(f"MQTT scan error: {e}")
    finally:
        sock.close()
    return False
