#!/usr/bin/python3

from scapy.all import *




class TWAMPTestQuery(Packet):
    name = "TWAMPQuery"
    fields_desc=[IntField("SequenceNumber",0),
                    LongField("TransmitCounter",0),
                    BitEnumField("X",1,1,{0: "32bit Counter", 
                                          1: "64bit Counter"}),
                    BitEnumField("B",0,1,{0: "Packet Counter", 
                                          1: "Octet Counter"}),
                    BitField("MBZ",0,6),
                    ByteField("BlockNumber",0),
                    ShortField("MBZ",0),
                    ThreeBytesField("MBZ",0),
                    ByteEnumField("SenderControlCode", 0, {0: "Out-of-band Response Requested",
                                                           1: "In-band Response Requested"})
                    ] #manca il padding
 

class TWAMPTestResponse(Packet):
    name = "TWAMPResponse"
    fields_desc=[IntField("SequenceNumber",0),
                    LongField("TransmitCounter",0),
                    BitField("X",0,1),
                    BitField("B",0,1),
                    BitField("MBZ",0,6),
                    XByteField("BlockNumber",0),
                    ShortField("MBZ",0),
                    LongField("ReceiveCounter",0),
                    IntField("SenderSequenceNumber",0),
                    LongField("SenderCounter",0),
                    BitField("X2",0,1),
                    BitField("B2",0,1),
                    BitField("MBZ",0,6),
                    XByteField("SenderBlockNumber",0),
                    XByteField("MBZ",0),
                    ByteEnumField("ReceverControlCode", 0, {1: "Error - Invalid Message"}),
                    XByteField("SenderTTL",0)] #manca il padding

class TWAMPTPacketSender(Packet):
    name ="TWAMPPacketSender"
    fields_desc=[IntField("SequenceNumber",0),
                    BitField("FirstPartTimestamp",0,32),
                    BitField("SecondPartTimestamp",0,32),
                    BitEnumField("S", 0, 1, {0: " no external synchronization",
                                             1: "external synchronization"}),
                    BitField("Z",0,1),
                    BitField("Scale",0,6),
                    BitField("Multiplier",0,8)] #manca il padding


class TWAMPTPacketReflector(Packet):
    name ="TWAMPPacketReflector"
    fields_desc=[IntField("SequenceNumber",0),
                    BitField("FirstPartTimestamp",0,32),
                    BitField("SecondPartTimestamp",0,32),
                    BitEnumField("S", 0, 1, {0: " no external synchronization",
                                             1: "external synchronization"}),
                    BitField("Z",0,1),
                    BitField("Scale",0,6),
                    BitField("Multiplier",0,8),
                    BitField("MBZ",0,16),
                    BitField("FirstPartTimestampReceiver",0,32),
                    BitField("SecondPartTimestampReceiver",0,32),
                    IntField("SequenceNumberSender",0),
                    BitField("FirstPartTimestampSender",0,32),
                    BitField("SecondPartTimestampSender",0,32),
                    BitEnumField("SSender", 0, 1, {0: " no external synchronization",
                                             1: "external synchronization"}),
                    BitField("ZSender ",0,1),
                    BitField("ScaleSender",0,6),
                    BitField("MultiplierSender",0,8),
                    BitField("MBZ",0,16),
                    ByteField("SenderTTL",255)] #manca il padding