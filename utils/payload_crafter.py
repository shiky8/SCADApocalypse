import random
import struct
import logging

logger = logging.getLogger('payload_crafter')

def random_bytes(length):
    return bytes(random.getrandbits(8) for _ in range(length))

def craft_modbus_payload():
    # Modbus function code 0x05 (Write Single Coil) example with fuzzed address and value
    function_code = 0x05
    address = random.randint(0, 0xFFFF)
    value = random.choice([0x0000, 0xFF00])  # Off or On
    payload = struct.pack('>BHH', function_code, address, value)
    logger.debug(f"Crafted Modbus payload: {payload.hex()}")
    return payload

def craft_ethernetip_payload():
    # Simplified EtherNet/IP Write Request with fuzzed data (placeholder)
    header = b'\x00\x00\x00\x00'  # Placeholder header
    data = random_bytes(20)
    payload = header + data
    logger.debug(f"Crafted EtherNet/IP payload: {payload.hex()}")
    return payload

def craft_dnp3_payload():
    # DNP3 packet with random control and data fields
    control = random.randint(0, 0xFF)
    data = random_bytes(10)
    payload = struct.pack('B', control) + data
    logger.debug(f"Crafted DNP3 payload: {payload.hex()}")
    return payload

def craft_iec104_payload():
    # IEC-104 APDU with fuzzed ASDU type and cause of transmission
    start_byte = 0x68
    length = 0x0E
    apdu = bytearray([start_byte, length])
    apdu += random_bytes(length)
    logger.debug(f"Crafted IEC-104 payload: {apdu.hex()}")
    return bytes(apdu)

def craft_s7comm_payload():
    # S7Comm packet with fuzzed bytes
    base_packet = bytearray.fromhex("0300001602f080320100000000000000000000000000")
    idx = random.randint(0, len(base_packet) - 1)
    base_packet[idx] = random.randint(0, 255)
    logger.debug(f"Crafted S7Comm payload: {base_packet.hex()}")
    return bytes(base_packet)
