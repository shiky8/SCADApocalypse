import socket
from utils.logger import setup_logger

logger = setup_logger()

def build_s7_read_var_packet():
    return (
        b'\x03\x00\x00\x1f'              # TPKT
        b'\x02\xf0\x80'                  # COTP
        b'\x32\x01\x00\x00\x00\x01'      # S7 header (Job)
        b'\x00\x0e\x00\x00'              # Params/Data lengths
        b'\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x84\x00\x00\x00'
    )

def build_s7_plc_status_packet():
    return (
        b'\x03\x00\x00\x21'
        b'\x02\xf0\x80'
        b'\x32\x01\x00\x00\x00\x01'
        b'\x00\x12\x00\x00'
        b'\x04\x01\x12\x0a\x10\x09\x00\x01\x00\x00\x00\x01\x12\x00\x00\x00'
    )

def scan(target, port=102, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))

        # Send initial S7Comm negotiation (CR)
        cr = (
            b'\x03\x00\x00\x16'
            b'\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02'
        )
        sock.send(cr)
        sock.recv(256)

        # Send Read Var packet
        sock.send(build_s7_read_var_packet())
        rsp = sock.recv(256)
        if b'\x32' in rsp:
            logger.info(f"[+] S7Comm ReadVar response from {target}:{port} => {rsp}")

        # Send PLC Status packet
        sock.send(build_s7_plc_status_packet())
        rsp = sock.recv(256)
        if b'\x32' in rsp:
            logger.info(f"[+] S7Comm PLC Status response from {target}:{port} => {rsp}")
            return True

    except Exception as e:
        logger.debug(f"S7Comm scan error: {e}")
    finally:
        sock.close()
    return False
