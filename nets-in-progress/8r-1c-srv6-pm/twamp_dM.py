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



class Reflector(TWAMPUtils):
        
        def __init__(self,srcAddr):
              
                self.srcAddr = srcAddr
                self.senderSequenceNumber = 0
                self.senderTSint = 0
                self.senderTSfloat = 0


        def sendReflectorDelayPacket(self,dstAddr,sequence_number,scale=0,multiplier=1,mBZ=0,SSender=0,ZSender=0,scaleSender=0,multiplierSender=1):

            timestamp = self.getTimestamp()

            ipv6_packet = IPv6()
            ipv6_packet.src = self.srcAddr
            ipv6_packet.dst = dstAddr

            udp_packet = UDP()
            udp_packet.dport = 1206 
            udp_packet.sport = 1205
            

            twamp_reflector = twamp.TWAMPTPacketReflector(SequenceNumber = sequence_number, 
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

            self.srcAddr = packet[IPv6].dst
            dstAddr = packet[IPv6].src

            packet[UDP].decode_payload_as(twamp.TWAMPTPacketSender)

            sequence_number = packet[UDP].SequenceNumber
            self.senderSequenceNumber = packet[UDP].SequenceNumber
            self.senderTSint = packet[UDP].FirstPartTimestamp
            self.senderTSfloat = packet[UDP].SecondPartTimestamp

            self.sendReflectorDelayPacket(sequence_number,dstAddr)

            


class Sender(TWAMPUtils):

    def __init__(self, srcAddr, dstAddr):
        self.srcAddr = srcAddr
        self.dstAddr = dstAddr
        self.SequenceNumber = 0
        self.lastDelayMeasured = 0
        self.avarageDelayMeasured = 0
        self.maxPacketSent = 500

    def sendSenderDelayPacket(self,scale=0,multiplier=1):

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
                                Scale = scale, 
                                Multiplier = multiplier)

        pkt = (ipv6_packet / udp_packet / twampPaylod)

        send(pkt, count=1)



    def recvTWAMPfromReflector(self, packet):

        packet[UDP].decode_payload_as(twamp.TWAMPTPacketSender)

        if ( packet[UDP].SequenceNumber == self.SequenceNumber):

                delay = (packet[UDP].FirstPartTimestampReceiver + packet[UDP].SecondPartTimestampReceiver) - (packet[UDP].FirstPartTimestampSender + packet[UDP].SecondPartTimestampSender)
          
                if ( self.maxPacketSent >= self.SequenceNumber):
                    return
                else:
                    self.SequenceNumber = packet[UDP].SequenceNumber +1 
                    sendSenderDelayPacket()

        else:
            #pacchetto scartato
            return 
