import socket
import struct
from utils.logger import setup_logger

logger = setup_logger()

# DNP3 function ID mappings (simplified)
FUNCTION_CODES = {
    0x00: "ACK",
    0x01: "NACK",
    0x0B: "Link Status",
    0x0F: "User Data",
    0x02: "TEST Link",
    0x03: "User Data (PRM=1)",
    0x09: "Request Link Status",
}

def parse_control_byte(ctrl):
    """Parse control byte into DIR, PRM, and Function"""
    dir_bit = (ctrl & 0x80) >> 7
    prm_bit = (ctrl & 0x40) >> 6
    func_code = ctrl & 0x3F  # Lower 6 bits
    function_name = FUNCTION_CODES.get(func_code, "Unknown")

    return dir_bit, prm_bit, func_code, function_name

def scan(target, port=20000, timeout=10):
    logger.info(f"[*] Starting DNP3 scan on {target}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    # Basic Link Status request to address 0x0000 from source 0x0001
    dnp3_request = b'\x05\x64\x0B\xC4\x00\x00\x01\x00\x00\x00'

    try:
        sock.connect((target, port))
        logger.info(f"[*] Connected to {target}:{port}")
        logger.debug(f"[*] Sending DNP3 request: {dnp3_request.hex()}")
        sock.send(dnp3_request)

        rsp = sock.recv(1024)
        logger.debug(f"[*] Raw response: {rsp.hex()}")

        if rsp.startswith(b'\x05\x64'):
            logger.info(f"[+] DNP3 response received from {target}:{port}")

            ctrl = rsp[2]
            dst, src = struct.unpack("<HH", rsp[4:8])  # Little endian

            dir_bit, prm_bit, func_code, func_name = parse_control_byte(ctrl)

            logger.info(f"    Destination Address: {dst}")
            logger.info(f"    Source Address: {src}")
            logger.info(f"    Control: {func_name} (Func Code: {func_code})")
            logger.info(f"    PRM: {prm_bit}, DIR: {dir_bit}")
            return {
                "Source Address": src,
                "Destination Address": dst,
                "Control": func_name,
                "Func Code": func_code,
                "PRM": prm_bit,
                "DIR": dir_bit
            }
        else:
            logger.warning(f"[-] Invalid DNP3 header received from {target}:{port}")
    except Exception as e:
        logger.error(f"[!] DNP3 scan error on {target}:{port} - {e}")
    finally:
        sock.close()
        logger.debug(f"[*] Closed connection to {target}:{port}")
    return None
