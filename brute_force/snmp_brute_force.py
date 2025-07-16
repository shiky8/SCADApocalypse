from concurrent.futures import ThreadPoolExecutor, as_completed
from pysnmp.hlapi import *
from utils.logger import setup_logger
from utils.scadapass_updater import load_scadapass_credentials

logger = setup_logger()

def try_snmp_community(target, port, community, oid='1.3.6.1.2.1.1.1.0', timeout=2):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # SNMP v2c
            UdpTransportTarget((target, port), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            return None
        elif errorStatus:
            return None
        else:
            result = f"{varBinds[0][0]} = {varBinds[0][1]}"
            logger.info(f"[✓] Valid SNMP community string: {community} | {result}")
            return (community, result)
    except Exception as e:
        logger.debug(f"[!] SNMP error with {community}: {e}")
    return None


def snmp_brute_force_with_scadapass(target, scadapass_file=None, system_name=None, port=161, max_workers=20):
    communities = []

    creds = load_scadapass_credentials(scadapass_file) if scadapass_file else {}

    if system_name and system_name in creds:
        communities = [c for _, c in creds[system_name]]
    else:
        for v in creds.values():
            communities.extend([c for _, c in v])

    communities = list(set(communities)) or ['public', 'private', 'community', 'admin']

    logger.info(f"[*] Starting SNMP brute force on {target}:{port} with {len(communities)} community strings")

    valid = None
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(try_snmp_community, target, port, community)
            for community in communities
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid = result
                break

    if not valid:
        logger.info("[!] No valid SNMP community string found")
    return valid
