import socket, struct
from utils.logger import setup_logger
logger = setup_logger()

def scan(target, port=1962, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))

        # Send PCWorx protocol ID request
        req = b'\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00'
        sock.send(req)
        rsp = sock.recv(512)

        if rsp and rsp.startswith(b'\x03'):
            logger.info(f"[+] PCWorx detected on {target}:{port}")
            logger.debug(f"[Raw Response] {rsp.hex()}")

            # Attempt to extract readable info from the response (often contains plaintext strings)
            try:
                # Extract possible human-readable info
                printable = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in rsp])
                logger.info(f"[+] PCWorx Info: {printable}")
            except Exception as info_err:
                logger.debug(f"[!] PCWorx info parse error: {info_err}")

            return True

    except Exception as e:
        logger.debug(f"PCWorx scan error: {e}")
    finally:
        sock.close()
    return False
