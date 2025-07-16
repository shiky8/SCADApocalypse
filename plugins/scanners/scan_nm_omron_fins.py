import socket
import time
from utils.logger import setup_logger

logger = setup_logger()

def scan(target, port=9600, timeout=5):
    logger.info(f"[*] Starting Omron FINS TCP scan on {target}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target, port))
        logger.debug("[*] Connected to target")

        # Step 1: FINS TCP Handshake
        fins_header = b'FINS' + b'\x00\x0c' + b'\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'
        sock.send(fins_header)

        try:
            rsp = sock.recv(1024)
            if not rsp:
                logger.debug("[*] Empty response received, retrying after short delay...")
                time.sleep(1)
                rsp = sock.recv(1024)
        except socket.timeout:
            logger.warning("[-] Socket timed out waiting for handshake response")
            return {
                "status": "timeout",
                "target": target,
                "port": port,
                "error": "Handshake timeout"
            }

        if not rsp.startswith(b'FINS'):
            logger.warning(f"[-] Response does not start with 'FINS': {rsp[:4].hex() if rsp else 'no response'}")
            return {
                "status": "invalid_handshake",
                "target": target,
                "port": port,
                "error": "Invalid or empty handshake"
            }

        if len(rsp) < 24:
            logger.warning(f"[-] FINS handshake response too short: length={len(rsp)}")
            return {
                "status": "invalid_handshake",
                "target": target,
                "port": port,
                "error": f"Short handshake response: {rsp.hex()}"
            }

        logger.info("[+] FINS TCP handshake successful")
        logger.debug(f"[Raw Handshake Response] {rsp.hex()}")

        # Extracting node address from response (byte 19)
        node = rsp[19]

        # Step 2: Build and send FINS command to read 1 word from DM area
        fins_cmd = (
            b'\x80'              # ICF
            b'\x00'              # RSV
            b'\x02'              # GCT
            b'\x00'              # DNA
            + bytes([node])      # DA1
            + b'\x00'           # DA2
            b'\x00'              # SNA
            b'\x10'              # SA1 (arbitrary source address)
            b'\x00'              # SA2
            b'\x01'              # SID
            b'\x01\x01'          # Command: Memory Area Read
            b'\x00\x00'          # Subcommand
            b'\x82'              # Memory area: DM Area
            b'\x00\x00'          # Address: 0000
            b'\x00'              # Bit address
            b'\x00\x01'          # Read 1 word
        )

        fins_tcp_header = b'\x00\x00\x00\x02' + len(fins_cmd).to_bytes(4, 'big') + b'\x00\x00\x00\x00'
        packet = fins_tcp_header + fins_cmd

        sock.send(packet)
        logger.debug(f"[FINS CMD Sent] {packet.hex()}")

        try:
            cmd_rsp = sock.recv(1024)
        except socket.timeout:
            logger.error(f"[!] FINS TCP scan error on {target}:{port} - timed out")
            return {
                "status": "timeout",
                "target": target,
                "port": port,
                "error": "FINS command timeout"
            }

        if not cmd_rsp:
            logger.warning("[-] No response to FINS command")
            return {
                "status": "no_response",
                "target": target,
                "port": port,
                "error": "No data from FINS command"
            }

        logger.info(f"[+] FINS CMD Response from {target}:{port}")
        logger.debug(f"[Raw CMD Response] {cmd_rsp.hex()}")

        return {
            "status": "success",
            "target": target,
            "port": port,
            "raw_response": cmd_rsp.hex(),
        }

    except Exception as e:
        logger.error(f"[!] FINS TCP scan error on {target}:{port} - {e}")
        return {
            "status": "error",
            "target": target,
            "port": port,
            "error": str(e)
        }

    finally:
        sock.close()
        logger.debug(f"[*] Disconnected from {target}:{port}")
