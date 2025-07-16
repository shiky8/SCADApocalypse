import socket
from utils.logger import setup_logger
logger = setup_logger()


def parse_asdu(data):
    try:
        if len(data) < 15:
            logger.warning("[!] Response too short for ASDU parsing")
            return

        type_id = data[6]
        vsq = data[7]
        cot = data[8]
        originator = data[9]
        common_address = data[10] + (data[11] << 8)
        ioa = data[12] + (data[13] << 8) + (data[14] << 16)

        logger.info(f"[ASDU] Type ID: 0x{type_id:02X} ({type_id})")
        logger.info(f"[ASDU] Variable Structure Qualifier (VSQ): 0x{vsq:02X} (Num Objects: {vsq & 0x7F}, SQ: {(vsq & 0x80) >> 7})")
        logger.info(f"[ASDU] Cause of Transmission (COT): 0x{cot:02X}")
        logger.info(f"[ASDU] Originator Address: 0x{originator:02X}")
        logger.info(f"[ASDU] Common Address: {common_address}")
        logger.info(f"[ASDU] Information Object Address (IOA): {ioa}")

    except Exception as e:
        logger.warning(f"[!] Failed to parse ASDU: {e}")


def scan(target, port=2404, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    logger.info(f"[*] Starting IEC-104 scan on {target}:{port}")

    try:
        sock.connect((target, port))
        logger.debug("[*] TCP connection established")

        # STARTDT act (U-Frame)
        req = b'\x68\x04\x07\x00\x00\x00'
        logger.debug(f"[*] Sending STARTDT act packet: {req.hex()}")
        sock.send(req)

        rsp = sock.recv(256)
        logger.debug(f"[*] Raw response: {rsp.hex()}")

        if rsp and rsp.startswith(b'\x68'):
            logger.info(f"[+] IEC-104 detected on {target}:{port}")
            hex_dump = ' '.join(f'{b:02x}' for b in rsp)
            logger.info(f"[+] Full hex response: {hex_dump}")

            # Parse TX and RX sequence numbers from control field
            tx = ((rsp[2] | (rsp[3] << 8)) >> 1)
            rx = ((rsp[4] | (rsp[5] << 8)) >> 1)
            logger.info(f"[CTRL] TX Sequence #: {tx}")
            logger.info(f"[CTRL] RX Sequence #: {rx}")

            # If it's an I-Frame (starts with 0x68 and byte 2 is even), parse ASDU
            if (rsp[2] & 0x01) == 0:
                parse_asdu(rsp)

            return True

    except Exception as e:
        logger.error(f"[!] IEC-104 scan error on {target}:{port} - {e}")
    finally:
        sock.close()
        logger.debug(f"[*] Closed connection to {target}:{port}")

    return False
