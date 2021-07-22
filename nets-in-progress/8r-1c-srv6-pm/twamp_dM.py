from scapy.all import *
from scapy.layers.inet import IP,UDP
from scapy.layers.inet6 import IPv6
import twamp
from datetime import datetime
from threading import Thread
import time



class TWAMPDelayMeasurement(Thread):

    def __init__(self, interface=get_if_list(), sender=None, reflector=None):

        Thread.__init__(self)
        self.interface = interface
        self.SessionSender = sender
        self.SessionReflector = reflector

    def packetRecvCallback(self, packet):

        #TODO passate dal controller per connessione!!!
        if UDP in packet:
            if packet[UDP].dport==1205:
                packet[UDP].decode_payload_as(twamp.TWAMPTPacketSender)
                print(packet.show())
                if(self.SessionReflector != None):
                    self.SessionReflector.recvTWAMPfromSender(packet)

            elif packet[UDP].dport==1206:
                packet[UDP].decode_payload_as(twamp.TWAMPTPacketReflector)
                print(packet.show())
                if(self.SessionSender != None):
                    self.SessionSender.recvTWAMPfromReflector(packet)

    def run(self):

        print("TestPacketReceiver Start sniffing...")
        sniff(iface=self.interface, filter="ip6", prn=self.packetRecvCallback)
        print("TestPacketReceiver Stop sniffing")


class TWAMPUtils():

    def __init__(self):
        print("Util class")

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



class Reflector(TWAMPUtils):
        
        def __init__(self,srcAddr,dstAddr):

                self.SequenceNumber = 0
                self.srcAddr = srcAddr
                self.dstAddr = dstAddr
                self.senderSequenceNumber = 0
                self.senderTSint = 0
                self.senderTSfloat = 0


        def receiveDelayPacket(self,scale=0,multiplier=0,mBZ=0,SSender=0,ZSender=0,scaleSender=0,multiplierSender=0):

            timestamp = self.getTimestamp()

            ipv6_packet = IPv6()
            ipv6_packet.src = self.srcAddr
            ipv6_packet.dst = self.dstAddr

            udp_packet = UDP()
            udp_packet.dport = 1206 
            udp_packet.sport = 1205
            

            twamp_reflector = twamp.TWAMPTPacketReflector(SequenceNumber = self.SequenceNumber, 
                                                        FirstPartTimestamp = timestamp[0],
                                                        SecondPartTimestamp = timestamp[1],
                                                        Scale = scale,
                                                        Multiplier = multiplier,
                                                        MBZ = mBZ,
                                                        FirstPartTimestampReceiver = timestamp[0],
                                                        SecondPartTimestampReceiver = timestamp[1],
                                                        SequenceNumberSender = self.senderSequenceNumber,
                                                        FirstPartTimestampSender = self.senderTSint,
                                                        SecondPartTimestampSender = self.senderTSfloat,
                                                        ScaleSender = scaleSender,
                                                        MultiplierSender = multiplierSender
                                                        )
            pkt = (ipv6_packet / udp_packet / twamp_reflector)

            send(pkt, count=1)

        def recvTWAMPfromSender(self, packet):

            print("TODO")


class Sender(TWAMPUtils):

    def __init__(self, srcAddr, dstAddr):
        self.srcAddr = srcAddr
        self.dstAddr = dstAddr
        self.SequenceNumber = 0

    def sendDelayPacket(self,scale=0,multiplier=0):

        timestamp = self.getTimestamp()
        ipv6_packet = IPv6()
        ipv6_packet.src = self.srcAddr
        ipv6_packet.dst = self.dstAddr

        #TODO parte Srv6 qui

        udp_packet = UDP()
        udp_packet.dport = 1205 
        udp_packet.sport = 1206 

        twampPaylod = twamp.TWAMPTPacketSender(SequenceNumber = self.SequenceNumber, 
                                FirstPartTimestamp = timestamp[0],
                                SecondPartTimestamp = timestamp[1],
                                Scale = self.intToBitField(6,scale), 
                                Multiplier = self.intToBitField(8,multiplier))

        pkt = (ipv6_packet / udp_packet / twampPaylod)

        send(pkt, count=1)



    def recvTWAMPfromReflector(self, packet):

        print("TODO")