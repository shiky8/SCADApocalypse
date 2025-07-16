import requests
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=8080, timeout=3):
    url = f"http://{target}:{port}/"
    try:
        r = requests.get(url, timeout=timeout)
        if "OpenPLC" in r.text:
            logger.info(f"OpenPLC detected on {target}:{port}")
            return True
    except Exception as e:
        logger.debug(f"OpenPLC scan error: {e}")
    return False