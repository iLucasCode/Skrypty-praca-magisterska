from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING

def modify_snmp_packet(packet):
    scapy_packet = IP(packet.get_payload())
    
    if scapy_packet.haslayer(SNMP):
        snmp_layer = scapy_packet.getlayer(SNMP)
        modified = False
        print(f"PDU Type: {snmp_layer.PDU.__class__.__name__}")
       
        if snmp_layer.PDU.name == "SNMPresponse":
            varbinds = snmp_layer.PDU.varbindlist
            print("ok")
            for varbind in varbinds:
                oid = varbind.oid.val
                if oid == '1.3.6.1.2.1.1.5.0':
                    print(f"Changing system.sysContact from {varbind.value} to 'FAKEVALUE'")
                    varbind.value = ASN1_STRING('FAKEVALUE')
                    modified = True

        if modified:
            if scapy_packet.haslayer(IP):
                del scapy_packet[IP].chksum
                scapy_packet[IP].len = None
            if scapy_packet.haslayer(UDP):
                del scapy_packet[UDP].chksum
                scapy_packet[UDP].len = None

            packet.set_payload(bytes(scapy_packet))
    
    packet.accept()

def main():
    queue = NetfilterQueue()
    queue.bind(1, modify_snmp_packet)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("Program terminated")

if __name__ == "__main__":
    main()

