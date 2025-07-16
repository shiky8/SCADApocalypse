import socket
import struct
from utils.logger import setup_logger
logger = setup_logger()

def scan(target, port=4840, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))

        # OPC UA Hello message
        req = (
            struct.pack(">I", 56) +      # Message size
            b'HEL' +                     # Message type
            b'\x00' +                    # Reserved
            b'OPC UA Client\x00' +       # Client name
            b'\x01\x00\x00\x00' +        # ProtocolVersion = 1
            b'\x00\x40\x00\x00' +        # ReceiveBufferSize = 16384
            b'\x00\x40\x00\x00' +        # SendBufferSize = 16384
            b'\x00\x00\x10\x00' +        # MaxMessageSize = 1048576
            b'\x04\x00\x00\x00' +        # MaxChunkCount = 4
            b'\x00\x00'                  # EndpointURL length = 0 (None)
        )

        sock.send(req)
        rsp = sock.recv(1024)

        if rsp and b'ACK' in rsp:
            logger.info(f"[+] OPC UA server detected on {target}:{port}")
            logger.debug(f"[Raw ACK Response] {rsp.hex()}")

            # Parse known values (starting after the header = 8 bytes)
            header_size = 8
            offset = header_size

            # Extract fields
            protocol_version = struct.unpack_from("<I", rsp, offset)[0]
            offset += 4
            recv_buf = struct.unpack_from("<I", rsp, offset)[0]
            offset += 4
            send_buf = struct.unpack_from("<I", rsp, offset)[0]
            offset += 4
            max_msg = struct.unpack_from("<I", rsp, offset)[0]
            offset += 4
            max_chunk = struct.unpack_from("<I", rsp, offset)[0]
            offset += 4
            endpoint_len = struct.unpack_from("<H", rsp, offset)[0]
            offset += 2
            endpoint = rsp[offset:offset+endpoint_len].decode(errors='ignore')

            # Log parsed info
            logger.info(f"  ├─ Protocol Version : {protocol_version}")
            logger.info(f"  ├─ Receive Buffer   : {recv_buf}")
            logger.info(f"  ├─ Send Buffer      : {send_buf}")
            logger.info(f"  ├─ Max Message Size : {max_msg}")
            logger.info(f"  ├─ Max Chunk Count  : {max_chunk}")
            logger.info(f"  └─ Endpoint URL     : {endpoint if endpoint else '[None]'}")

            return True

    except Exception as e:
        logger.debug(f"OPC UA scan error: {e}")
    finally:
        sock.close()
    return False
