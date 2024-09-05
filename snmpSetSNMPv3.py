from pysnmp.hlapi import *

target_ip = "10.0.3.5" # Adres IP zmienniany w zależności od adresu urządzenia do którego ma zostać wysłane żądanie SNMP SET
target_oid = '1.3.6.1.2.1.1.5.0'
value_set = "HACKED"

# Wartości zmieniane zależnie od konfiguracji agenta SNMP skonfigurowanego na urządzeniu o adresie "target_ip"
user = "PC3" 
auth_protocol = usmHMACMD5AuthProtocol
auth_password = "authpass"
priv_protocol = usmAesCfb128Protocol
priv_password = "privpass"

errorIndication, errorStatus, errorIndex, varBinds = next(
    setCmd(
        SnmpEngine(),
        UsmUserData(
            user,
            authKey=auth_password, # nie używane w przypadku SNMPv3 noAuthNoPriv
            authProtocol=auth_protocol, # nie używane w przypadku SNMPv3 noAuthNoPriv
            privKey=priv_password, # nie używane w przypadku SNMPv3 authNoPriv oraz noAuthNoPriv
            privProtocol=priv_protocol # nie używane w przypadku SNMPv3 authNoPriv oraz noAuthNoPriv
        ),
        UdpTransportTarget((target_ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(target_oid), value_set)
    )
)

if errorIndication:
    print(f"Error: {errorIndication}")
elif errorStatus:
    print(f"Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
else:
    print('Set operation successful')