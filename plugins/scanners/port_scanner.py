import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import setup_logger
from utils.cve_matcher import cve_search


logger = setup_logger()

def scan_port(target, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            logger.info(f"Port {port} is open")
            return port
    except Exception as e:
        logger.error(f"Error scanning port {port}: {e}")
    finally:
        sock.close()
    return None

def scan_tcp_ports(target, start_port=1, end_port=10024, max_workers=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in range(start_port, end_port + 1)}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    if not open_ports:
        logger.error(f"can't find any open port ")
    return sorted(open_ports)

def scan_udp_ports(target, ports=[502, 20000, 44818], timeout=1):
    open_ports = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    for port in ports:
        try:
            sock.sendto(b'\x00', (target, port))
            data, _ = sock.recvfrom(1024)
            logger.info(f"UDP port {port} is open")
            open_ports.append(port)
        except socket.timeout:
            continue
        except Exception as e:
            logger.error(f"UDP scan error on port {port}: {e}")
    sock.close()
    if not open_ports:
        logger.error(f"can't find any open port ")
    return open_ports

def detect_scada_services(target):
    scada_ports = {
    502: "Modbus/TCP",
    20000: "DNP3",
    102: "S7Comm",
    47808: "BACnet/IP-UDP",
    44818: "EtherNet/IP",
    1911: "Fox (Tridium Niagara)",
    4911: "Fox (Tridium Niagara SSL)",
    18245: "GE-SRTP",
    18246: "GE-EGD",
    2222: "PCWorx (Phoenix Contact)",
    9600: "Omron-FINS",
    53001: "Koyo-Ethernet",
    53002: "Koyo-Ethernet",
    53003: "Koyo-Ethernet",
    53004: "Koyo-Ethernet",
    44818: "CIP (EtherNet/IP)",
    2221: "CIP (EtherNet/IP)",
    44818: "CIP-Class1",
    4840: "OPC-UA-TCP",
    4843: "OPC-UA-TCP-SSL",
    1883: "MQTT (unencrypted)",
    8883: "MQTT (TLS)",
    2404: "IEC-60870-5-104",
    789: "Crimson (Red Lion)",
    18246: "EGD (GE)",
    18245: "SRTP (GE)",
    5094: "H1-Protocol (HIMA)",
    1962: "PCCC (Rockwell PCCC)",
    44818: "ENIP-TCP",
    2222: "ENIP-UDP",
    55000: "FINS-UDP (Omron)",
    9600: "FINS-TCP (Omron)",
    20547: "Modbus-RTPS",
    80: "HTTP-REST (custom SCADA)",
    443: "HTTPS-REST (custom SCADA)",
    161: "SNMP (SCADA devices)",
    623: "IPMI (SCADA servers)",
    789: "Red-Lion-Crimson",
    5094: "HIMA-H1",
    1962: "AB-PCCC",
    2221: "AB-EtherNet/IP",
    44818: "AB-CIP",
    18245: "GE-SRTP",
    18246: "GE-EGD",
    5094: "HIMA-H1",
    789: "Red-Lion-Crimson",
    5094: "HIMA-H1",
    1962: "AB-PCCC",
    2221: "AB-EtherNet/IP",
    44818: "AB-CIP",
    18245: "GE-SRTP",
    18246: "GE-EGD",
    5094: "HIMA-H1",
    789: "Red-Lion-Crimson",
    5094: "HIMA-H1",
    1962: "AB-PCCC",
    2221: "AB-EtherNet/IP",
    44818: "AB-CIP",
    18245: "GE-SRTP",
    18246: "GE-EGD",
    5094: "HIMA-H1",
    789: "Red-Lion-Crimson",
    5094: "HIMA-H1",
    1962: "AB-PCCC",
    2221: "AB-EtherNet/IP",
    44818: "AB-CIP",
    18245: "GE-SRTP",
    18246: "GE-EGD",
    5094: "HIMA-H1",
    789: "Red-Lion-Crimson",
    5094: "HIMA-H1",
    1962: "AB-PCCC",
    2221: "AB-EtherNet/IP",
    44818: "AB-CIP",
}
    detected = {}
    cve_results = {}
# for service, banner in scan_results.items():
    

    for port, service in scada_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            if sock.connect_ex((target, port)) == 0:
                detected[port] = service
                cve_results[service] = cve_search(service)
                logger.info(f"Detected {service} service on port {port}")
        except Exception as e:
            logger.error(f"Error detecting service on port {port}: {e}")
        finally:
            sock.close()
    if not detected:
        logger.error(f"can't detected  the SCADA system ")
    return detected,cve_results

def scan(target,scan_type="detect_default_scada"):
    # print(f"{scan_type = }")
    d_rulte = {}
    if scan_type == "tcp_scan":
       d_rulte =  scan_tcp_ports(target)
    elif scan_type == "udp_scan":
        d_rulte =  scan_udp_ports(target)
    elif scan_type == "detect_default_scada":
        d_rulte =  detect_scada_services(target)
    return d_rulte 