import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=5025, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors='ignore')
        if "EcoStruxure" in banner or "Schneider" in banner:
            logger.info(f"EcoStruxure detected on {target}:{port} - Banner: {banner.strip()}")
            return True
    except Exception as e:
        logger.debug(f"EcoStruxure scan error: {e}")
    finally:
        sock.close()
    return False