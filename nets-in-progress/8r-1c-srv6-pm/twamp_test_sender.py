
from scapy.all import *
from scapy.layers.inet import IP,UDP

from scapy.layers.inet6 import IPv6
import twamp
import twamp_dM
import time

sender_file = open("IPv6-Sender", "r")
reflector_file = open("IPv6-Reflector", "r")

source_addr = sender_file.readline().split('\n')[0]
dst_addr = reflector_file.readline().split('\n')[0]

"""
i=IPv6() 
i.src = source_addr
i.dst = dst_addr

q=UDP()
q.dport = 1205 #TODO  me li da il controller?
q.sport = 1206 #TODO  me li da il controller?


t = twamp.TWAMPTestQuery(SequenceNumber=1, 
                                TransmitCounter=2,
                                BlockNumber=3,
                                SenderControlCode=1
                                )

pkt=(i/q/t)

send(pkt,count=50)
"""

sender = twamp_dM.Sender(source_addr, dst_addr)
t_dm = twamp_dM.TWAMPDelayMeasurement(sender=sender)

#sender is sniffing for response (?)
t_dm.start()
#print("After thread")
#time.sleep(2)
sender.sendDelayPacket()
time.sleep(2)
