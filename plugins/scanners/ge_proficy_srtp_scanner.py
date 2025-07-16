import socket

def scan(target, port=18245):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((target, port))
        # Send a simple SRTP probe packet (example)
        probe = b'\x01\x00\x00\x00'
        sock.send(probe)
        response = sock.recv(1024)
        if response:
            logger.info(f"GE Proficy SRTP service detected on {target}:{port}")
            return True
    except Exception:
        pass
    finally:
        sock.close()
    return False
