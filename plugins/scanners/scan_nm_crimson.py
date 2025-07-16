import socket
from utils.logger import setup_logger
logger = setup_logger()

def scan(target, port=789, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        # Crimson “HELLO”
        sock.send(b'HELLO')
        rsp = sock.recv(256)
        if rsp:
            rsp_str = rsp.decode(errors="ignore")
            if 'RED' in rsp_str.upper():
                logger.info(f"[+] Red Lion Crimson device detected on {target}:{port}")
                logger.info(f"    Raw Response : {rsp_str.strip()}")

                # Try to extract model/version if present
                if 'Crimson' in rsp_str:
                    lines = rsp_str.splitlines()
                    for line in lines:
                        if 'Crimson' in line:
                            logger.info(f"    Crimson Info : {line.strip()}")
                return True
    except Exception as e:
        logger.debug(f"Crimson scan error: {e}")
    finally:
        sock.close()
    return False
