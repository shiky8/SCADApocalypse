import socket, struct
from utils.logger import setup_logger
logger = setup_logger()

def scan(target, port=44818, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        # Send ListIdentity (command 0x63)
        req = b'\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        sock.send(req)
        rsp = sock.recv(512)

        if rsp and rsp.startswith(b'\x63\x00'):
            logger.info(f"[+] EtherNet/IP CIP device detected on {target}:{port}")

            # Skip 24-byte Encapsulation header
            payload = rsp[24:]

            # Check at least one identity item (38 bytes min)
            if len(payload) < 38:
                logger.warning("[-] Truncated ListIdentity response")
                return True

            # Skip first 4 bytes (Item count and Type ID)
            item = payload[4:]

            # Extract fields (according to ListIdentity reply format)
            vendor_id     = struct.unpack_from('<H', item, 4)[0]
            device_type   = struct.unpack_from('<H', item, 6)[0]
            product_code  = struct.unpack_from('<H', item, 8)[0]
            revision_major = item[10]
            revision_minor = item[11]
            status        = struct.unpack_from('<H', item, 12)[0]
            serial_number = struct.unpack_from('<I', item, 14)[0]

            # Product name length-prefixed string
            name_len = item[18]
            product_name = item[19:19+name_len].decode(errors='ignore')

            logger.info(f"    Vendor ID     : {vendor_id}")
            logger.info(f"    Device Type   : {device_type}")
            logger.info(f"    Product Code  : {product_code}")
            logger.info(f"    Revision      : {revision_major}.{revision_minor}")
            logger.info(f"    Serial Number : {serial_number}")
            logger.info(f"    Product Name  : {product_name}")

            return True

    except Exception as e:
        logger.debug(f"CIP scan error: {e}")
    finally:
        sock.close()
    return False
