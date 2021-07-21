
from scapy.all import *
from scapy.layers.inet import IP,UDP

from scapy.layers.inet6 import IPv6,IPv6ExtHdrSegmentRouting
import twamp
import time

source_addr = "fe80::3b34:65ba:2422:139f"
dst_addr = "fe80::66d0:97f9:7087:dd22"

i=IPv6() 
i.src=source_addr
i.dst= dst_addr

q=UDP()
q.dport = 1205 #TODO  me li da il controller?
q.sport = 1206 #TODO  me li da il controller?



t = twamp.TWAMPTestQuery(SequenceNumber=1, 
                                TransmitCounter=2,
                                BlockNumber=3,
                                SenderControlCode=1)

pkt=(i/q/t)

send(pkt,count=50)


