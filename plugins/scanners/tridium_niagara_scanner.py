import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=1911, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        sock.send(b'GET / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode(errors='ignore')
        if "Niagara" in banner:
            logger.info(f"Tridium Niagara detected on {target}:{port}")
            return True
    except Exception as e:
        logger.debug(f"Tridium Niagara scan error: {e}")
    finally:
        sock.close()
    return False