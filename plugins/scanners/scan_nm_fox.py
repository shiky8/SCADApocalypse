import socket
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=1911, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    logger.info(f"[*] Starting Niagara Fox scan on {target}:{port}")

    try:
        logger.info("[*] Connecting...")
        sock.connect((target, port))

        # Full Niagara Fox handshake
        handshake = (
            b"fox a 1 -1 fox hello\n"
            b"{\n"
            b"fox.version=s:1.0\n"
            b"id=i:1\n"
            b"};;\n"
        )

        logger.info(f"[*] Sending handshake: {handshake!r}")
        sock.send(handshake)

        rsp = sock.recv(1024)
        logger.info(f"[*] Received raw response: {rsp!r}")

        if not rsp:
            logger.warning(f"[!] Empty response from {target}:{port}")
            return False

        # Updated check: look for 'fox a 0' instead of 'niagara'
        if rsp.lower().startswith(b'fox a 0'):
            logger.info(f"[+] Niagara Fox service detected on {target}:{port}")

            try:
                text = rsp.decode(errors='ignore')
                logger.info(f"[+] Decoded Text:\n{text}")

                # Extract and print relevant metadata
                for line in text.split('\n'):
                    if any(keyword in line.lower() for keyword in [
                        'station', 'niagara', 'version', 'host', 'brand',
                        'vm', 'timezone', 'os', 'lang'
                    ]):
                        logger.info(f"[i] Info Line: {line.strip()}")

            except Exception as decode_err:
                logger.warning(f"[!] Failed to decode response: {decode_err}")

            return True
        else:
            logger.info(f"[-] No valid Niagara Fox signature found on {target}:{port}")
    except Exception as e:
        logger.error(f"[!] Niagara Fox scan error on {target}:{port} - {e}")
    finally:
        sock.close()
        logger.debug(f"[*] Closed connection to {target}:{port}")
    
    return False
