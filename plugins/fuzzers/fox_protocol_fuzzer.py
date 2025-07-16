import socket
import binascii
from utils.payload_loader import load_payloads
from utils.logger import setup_logger

logger = setup_logger()

def fox_handshake(sock):
    """
    Performs the FOXP handshake and returns the session ID.
    """
    try:
        # Client Hello (FOXP magic + version + nonce)
        client_hello = binascii.unhexlify("464f58500000000000000000")
        logger.info(f"[>] Sending Client Hello: {client_hello.hex()}")
        sock.send(client_hello)

        response = sock.recv(1024)
        if not response:
            logger.error("[-] No Server Hello response received.")
            # return None

        logger.info(f"[<] Received Server Hello: {response.hex()}")

        # Extract session ID (e.g., 4 bytes after FOXP header)
        if response.startswith(b'FOXP'):
            # Example: FOXP (4) + version (1) + session ID (4) + ...
            session_id = response[5:9]
            logger.info(f"[+] Extracted session ID: {session_id.hex()}")
            return session_id
        else:
            logger.error("[-] Invalid Server Hello format.")
            # return None

    except Exception as e:
        logger.error(f"[!] Handshake failed: {e}")
        # return None

def fuzz(target, port=1911, payloads_file='fox_protocol_payloads.txt', iterations=100):
    payloads = load_payloads(payloads_file)
    if not payloads:
        logger.error("No Fox Protocol payloads loaded")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    try:
        sock.connect((target, port))
        logger.info(f"Connected to Fox Protocol on {target}:{port}")

        session_id = fox_handshake(sock)
        if not session_id:
            logger.error("Aborting fuzzing due to missing session.")
            return

        # Start fuzzing using valid session
        responses = {}
        for i in range(min(iterations, len(payloads))):
            payload_hex = payloads[i].strip()
            try:
                fuzz_data = binascii.unhexlify(payload_hex)
            except binascii.Error:
                logger.warning(f"Skipping invalid hex payload: {payload_hex}")
                continue

            # Build a valid FOXP header + session ID + fuzzed data
            header = b'FOXP' + b'\x00' + session_id  # FOXP + version + session ID
            packet = header + fuzz_data

            logger.info(f"Fuzzing ({i+1}): {packet.hex()}")
            try:
                sock.send(packet)
                response = sock.recv(1024)
                if response:
                    logger.info(f"Received {len(response)} bytes: {response.hex()}")
                    responses[payload_hex] = response.hex()
                else:
                    logger.warning(f"Fuzz iteration {i+1}: Empty response")
            except socket.timeout:
                logger.warning(f"Fuzz iteration {i+1}: No response (timeout)")
            except Exception as e:
                logger.error(f"Fuzz iteration {i+1}: Send/recv error: {e}")
        return True

    except Exception as e:
        logger.error(f"Fox Protocol fuzzing error: {e}")
    finally:
        sock.close()
        logger.info("Connection closed.")
