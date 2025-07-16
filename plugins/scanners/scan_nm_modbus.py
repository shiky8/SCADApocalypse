import socket
from utils.logger import setup_logger
logger = setup_logger()

def scan(target, port=502, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        logger.info(f"[+] Modbus/TCP detected on {target}:{port}")
        
        # Correct MBAP + Read Device ID Request
        req = b'\x00\x01\x00\x00\x00\x05\x01\x2B\x0E\x01\x00'
        sock.send(req)
        rsp = sock.recv(512)

        if not rsp or rsp[7] != 0x2B or rsp[8] != 0x0E:
            logger.warning(f"[-] Invalid Read Device ID response from {target}")
            return False

        # Parse the response
        uid = rsp[6]
        read_dev_id_code = rsp[9]
        conformity_level = rsp[10]
        more_follows = rsp[11]
        next_object_id = rsp[12]
        num_objects = rsp[13]

        index = 14
        device_info = {}

        for _ in range(num_objects):
            obj_id = rsp[index]
            obj_len = rsp[index + 1]
            obj_value = rsp[index + 2: index + 2 + obj_len].decode(errors='ignore')
            device_info[obj_id] = obj_value
            index += 2 + obj_len

        logger.info(f"[+] Modbus Device ID info from {target}:{port}:")
        for obj_id, value in device_info.items():
            logger.info(f"    ID {obj_id}: {value}")
        return True

    except Exception as e:
        logger.error(f"Modbus scan error: {e}")
    finally:
        sock.close()

    return False
