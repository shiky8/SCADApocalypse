import socket
import binascii
from utils.payload_loader import load_payloads
from utils.logger import setup_logger

logger = setup_logger()

def test_modbus_connection(sock):
    """
    Sends a valid Modbus read request to confirm communication.
    """
    test_payload = b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'
    sock.send(test_payload)
    try:
        response = sock.recv(1024)
        if response:
            logger.info(f"Test response: {response.hex()}")
            return True
        else:
            logger.warning("Test request sent, but no response received.")
            return False
    except socket.timeout:
        logger.warning("Initial connection test timed out")
        return False

def fuzz(target, port=502, payloads_file='modbus_payloads.txt', iterations=100):
    payloads = load_payloads(payloads_file)
    if not payloads:
        logger.error("No Modbus payloads loaded")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, port))
        logger.info(f"Connected to Modbus on {target}:{port}")

        if not test_modbus_connection(sock):
            logger.error("Target did not respond to valid Modbus request. Aborting fuzz.")
            return
        responses = {}

        for i in range(min(iterations, len(payloads))):
            payload_hex = payloads[i]
            try:
                payload = binascii.unhexlify(payload_hex)
            except binascii.Error:
                logger.warning(f"Invalid hex string in payloads file: {payload_hex}")
                continue

            logger.info(f"Trying Modbus payload = {payload.hex()}")

            try:
                sock.send(payload)
                response = sock.recv(1024)
                if response:
                    logger.info(f"Fuzz iteration {i+1}: Received {len(response)} bytes: {response.hex()}")
                    responses[payload_hex] = response.hex()

                    if response[7] & 0x80:  # Exception response
                        logger.warning(f"Modbus exception response: code {response[8]:02x}")
                else:
                    logger.warning(f"Fuzz iteration {i+1}: No response")
            except socket.timeout:
                logger.warning(f"Fuzz iteration {i+1}: No response (timeout)")
            except Exception as e:
                logger.error(f"Fuzz iteration {i+1}: Error while sending/receiving - {e}")
        return True,responses

    except Exception as e:
        logger.error(f"Modbus fuzzing error: {e}")
    finally:
        sock.close()
