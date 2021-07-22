from scapy.all import *
from scapy.layers.inet import IP,UDP
from scapy.layers.inet6 import IPv6
import twamp
from datetime import datetime



class Sender():

	 def __init__(self,srcAddr,dstAddr):

	 	self.SequenceNumber = 0
	 	self.srcAddr = srcAddr
	 	self.dstAddr = dstAddr

	 def sendDelayPacket(self,scale=0,multiplier=0):

	 	timestamp = self.getTimestamp()

	 	twampPaylod = twamp.TWAMPTPacketSender(
	 											SequenceNumber = self.SequenceNumber, 
	 											FirstPartTimestamp = self.intToBitField(32,timestamp[0]),
	 											SecondPartTimestamp = self.intToBitField(32,timestamp[1]),
	 											Scale = self.intToBitField(6,scale),
	 											Multiplier = self.intToBitField(8,multiplier)
	 										)

	 	ipv6_packet = IPv6()
        ipv6_packet.src = self.srcAddr 
        ipv6_packet.dst = self.dstAddr

        #TODO parte Srv6 qui

   		udp_packet = UDP()
        udp_packet.dport = 1205 
        udp_packet.sport = 1206 

        pkt = ipv6_packet / udp_packet / twampPaylod

        return pkt


     def getTimestamp(self):

     	t = datetime.timestamp(datetime.now())

     	intTimestamp = int(t)
     	floatTimestamp = int(str(t).split(".")[1])

     	return (intTimestamp,floatTimestamp)


     def intToBitField(self,size,val):

     	bitArray = [int(digit) for digit in bin(val)[2:]]

     	if ( len(bitArray) > size):
     			return [0]

     	for i in range(0,size-len(bitArray)):
     		bitArray.insert(0,0)

     	return bitArray




class Reflector():
	
	def __init__(self,srcAddr,dstAddr):

	 	self.SequenceNumber = 0
	 	self.srcAddr = srcAddr
	 	self.dstAddr = dstAddr
	 	self.senderSequenceNumber = 0
	 	self.senderTSint = 0
	 	self.senderTSfloat = 0


	def receiveDelayPacket(self,scale=0,multiplier=0,mBZ=0,SSender=0,ZSender=0,scaleSender=0,multiplierSender=0) :


        ipv6_packet = IPv6()
        ipv6_packet.src = self.srcAddr
        ipv6_packet.dst = self.dstAddr

        udp_packet = UDP()
        udp_packet.dport = 1206 
        udp_packet.sport = 1205 

        twamp_reflector = twamp.TWAMPTPacketReflector(SequenceNumber = self.SequenceNumber, 
        											  FirstPartTimestamp = self.intToBitField(32,timestamp[0]),
	 												  SecondPartTimestamp = self.intToBitField(32,timestamp[1]),
	 												  Scale = self.intToBitField(6,scale),
	 												  Multiplier = self.intToBitField(8,multiplier),
	 												  MBZ = self.intToBitField(16,mBZ),
        											  FirstPartTimestampReceiver = self.intToBitField(32,timestamp[0]),
        											  SecondPartTimestampReceiver = self.intToBitField(32,timestamp[1]),
        											  SequenceNumberSender = self.senderSequenceNumber,
        											  FirstPartTimestampSender = self.intToBitField(32,self.senderTSint),
        											  SecondPartTimestampSender = self.intToBitField(32,self.senderTSfloat),
        											  ScaleSender = self.intToBitField(6,scaleSender),
        											  MultiplierSender = self.intToBitField(8,multiplierSender),
        											  MBZ = self.intToBitField(16,mBZ)
        											  )	

        pkt = ipv6_packet / udp_packet / twamp_reflector



     def getTimestamp(self):

     	t = datetime.timestamp(datetime.now())

     	intTimestamp = int(t)
     	floatTimestamp = int(str(t).split(".")[1])

     	return (intTimestamp,floatTimestamp)


     def intToBitField(self,size,val):

     	bitArray = [int(digit) for digit in bin(val)[2:]]

     	if ( len(bitArray) > size):
     			return [0]

     	for i in range(0,size-len(bitArray)):
     		bitArray.insert(0,0)

     	return bitArray