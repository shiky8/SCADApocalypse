import asyncio
from pysnmp.smi import builder, view
from pysnmp.entity import engine
from pysnmp.hlapi.asyncio import *
from pysnmp.proto.api import v2c
from pysnmp.carrier.asyncio.dgram import udp

from utils.logger import setup_logger
logger = setup_logger()


async def scan_snmp(target, community='public', timeout=3):
    snmpEngine = engine.SnmpEngine()

    transportDispatcher = snmpEngine.transportDispatcher
    transportDispatcher.registerTransport(
        udp.domainName,
        udp.UdpAsyncioTransport().openClientMode()
    )

    # Build request PDU
    pdu = v2c.GetRequestPDU()
    v2c.apiPDU.setDefaults(pdu)
    v2c.apiPDU.setVarBinds(pdu, [ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))])
    v2c.apiPDU.setRequestID(pdu, 1)

    # Send SNMP GET
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        snmpEngine,
        CommunityData(community, mpModel=0),
        UdpTransportTarget((target, 161), timeout=timeout, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
    )

    if errorIndication:
        logger.warning(f"[!] SNMP error on {target}: {errorIndication}")
        return False
    elif errorStatus:
        logger.warning(f"[!] SNMP error: {errorStatus.prettyPrint()} at {errorIndex}")
        return False
    else:
        for name, val in varBinds:
            logger.info(f"[+] SNMP on {target}: {name} = {val}")
        return True


def scan(target, community='public', timeout=3):
    return asyncio.run(scan_snmp(target, community, timeout))
