import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=18245, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    logger.info(f"[*] Starting GE-SRTP scan on {target}:{port}")

    try:
        sock.connect((target, port))
        logger.debug("[*] Connected successfully")

        # GE SRTP “ID” packet
        req = b'\x02\x01\x00\x01\x00\x01\x00'
        logger.debug(f"[*] Sending request: {req}")
        sock.send(req)

        rsp = sock.recv(256)
        logger.debug(f"[*] Raw response: {rsp}")

        if rsp and rsp.startswith(b'\x02'):
            logger.info(f"[+] GE-SRTP detected on {target}:{port}")
            try:
                text = rsp.decode(errors='ignore')
                logger.info(f"[+] Decoded response: {text}")
                for line in text.split('\n'):
                    if any(keyword in line.lower() for keyword in ['cpu', 'firmware', 'srttp', 'ge', 'series']):
                        logger.info(f"[i] Device Info: {line.strip()}")
            except Exception as decode_error:
                logger.warning(f"[!] Failed to decode response: {decode_error}")
            return True
        else:
            logger.debug(f"[-] No SRTP signature found in response from {target}:{port}")
    except Exception as e:
        logger.error(f"[!] GE-SRTP scan error on {target}:{port} - {e}")
    finally:
        sock.close()
        logger.debug(f"[*] Connection to {target}:{port} closed")

    return False
