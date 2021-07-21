#!/usr/bin/python

from scapy.all import *
from scapy.layers.inet import IP,UDP
from scapy.layers.inet6 import IPv6,IPv6ExtHdrSegmentRouting

import twamp

#sniffing on ALL interfaces
all_interfaces = get_if_list()

def rcv(packet):
    print("Packets Recv Callback")
    if UDP in packet:
        if packet[UDP].dport==1205:
            packet[UDP].decode_payload_as(twamp.TWAMPTestQuery)
            print(packet.show())
            hexdump(packet[twamp.TWAMPTestQuery])
        else:
            print(packet.show())

# WARNING ! ! ! Scapy 2.4.5 has a BUG, and passing a list will raise an exeption
# 				The bug -> (https://github.com/secdev/scapy/issues/3191)
sniff(iface=all_interfaces, filter="ip6", prn=lambda x: rcv(x))

