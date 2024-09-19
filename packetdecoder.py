import os
import msgpack


# Header, 2 bytes:
# 1: 
hIFAC            = 0b10000000# 1 bit
hHeaderType      = 0b01000000# 1 bit
hContext         = 0b00100000# 1 bit
hPropagationType = 0b00010000# 1 bit
hDestinationType = 0b00001100# 2 bits
hPacketType      = 0b00000011# 2 bits
# 2: Hops

# Destination Field(s): 16-32 bytes
# 16 bytes hash1
# IF type2: 16 bytes hash2

# Context, 1 byte

# Data: Balance of packet


ContextEnum = {

  0x00: "None"


}

IFACEnum = {
  0x00: "Open          (0)",
  0x01: "Authenticated (1)"
}

HeaderEnum = {
  0x00: "Type 1        (0)",
  0x01: "Type 2        (1)"  
}

PropagationEnum = {
  0x00: "Broadcast    (00)",
  0x01: "Transport    (01)",
  0x02: "Reserved     (10)",
  0x03: "Reserved     (11)"
}

DestinationEnum = {
  0x00: "Single       (00)",
  0x01: "Group        (01)",
  0x02: "Plain        (10)",
  0x03: "Link         (11)"
}

HeaderContextEnum = {
  0x00: "Unknown       (0)",
  0x01: "Unknown       (1)"

}

AnnounceHeaderContextEnum = {
  0x00: "No Ratchet    (0)",
  0x01: "Ratchet       (1)"

}

PacketTypeEnum = {
  0x00: "Data         (00)",
  0x01: "Announce     (01)",
  0x02: "Link Request (10)",
  0x03: "Proof        (11)"
}

ContextEnum = {
  0x00: "None",
  0x01: "Resource",
  0x02: "Resource Advertisement",
  0x03: "Resource Part Request",
  0x04: "Resource Hashmap Update",
  0x05: "Resource Proof",
  0x06: "Resource Initiator Cancel",
  0x07: "Resource Receiver Cancel",
  0x08: "Cache Request",
  0x09: "Request",
  0x0a: "Response",
  0x0b: "Path Response",
  0x0c: "Command",
  0x0d: "Command Status",
  0x0e: "Channel",
  0xfa: "Keepalive",
  0xfb: "Link Peer Identification Proof",
  0xfc: "Link Close",
  0xfd: "Link Proof",
  0xfe: "Link Request Time Measurement",
  0xff: "Link Request Proof"
  
}

Codes = {
  "Announce": 0x01,
  "Ratchet": 0x01
}

def GetContext(con):
  if con in ContextEnum:
    return ContextEnum[con]
  else:
    return "Undefined - "+str(hex(con))


def GetDirectory(path):
  buffer = []
  contents = os.listdir(path)
  for f in contents:
    if(os.path.isfile(os.path.join(path,f))):
      buffer.append(f)
  #print(contents)
  #print(buffer)
  return buffer

def ParsePacket(path):    
  print("")
  print("")
  print("")
  print("##################")
  print("### NEW PACKET ###")
  print("##################")
  print("")
  with open(path,'rb') as packet:
    wholefile = packet.read()
    #print(wholefile.hex())
    
  # Header 
  IFAC = (hIFAC&wholefile[0])>>7
  HeaderType = (hHeaderType&wholefile[0])>>6
  HeaderContext = (hContext&wholefile[0])>>5
  PropagationType = (hPropagationType&wholefile[0])>>4
  DestinationType = (hDestinationType&wholefile[0])>>2
  PacketType = hPacketType&wholefile[0]
  
  Hops = wholefile[1]
    

  # print(bin(wholefile[0]).replace("0b",""))
  print("### Header ###")
  print("IFAC:             "+IFACEnum[IFAC])
  print("Header Type:      "+HeaderEnum[HeaderType])
  if PacketType == 1:
    print("Header Context:   "+AnnounceHeaderContextEnum[HeaderContext])
  else:
    print("Header Context:   "+HeaderContextEnum[HeaderContext])
  print("Propagation Type: "+PropagationEnum[PropagationType])
  print("Destination Type: "+DestinationEnum[DestinationType])
  print("Packet Type:      "+PacketTypeEnum[PacketType])
  
  # print(wholefile[1])
  print("Hops:             "+str(Hops))
  
  HashOne = wholefile[2:18]
  if(HeaderType == 1):
    HashTwo = wholefile[18:34]
  
  print("")
  print("### Hash(es) ###")
  print("Hash1: "+str(HashOne.hex()))
  if(HeaderType == 1):
    print("Hash2: "+str(HashTwo.hex()))
  else:
    print("Hash2: N/A")
    
  print("")
  print("### Context ###")
  if(HeaderType==1):
    Context = wholefile[34]
  else:
    Context = wholefile[18]
  print("Context: "+GetContext(Context))
  print("")
  if(HeaderType==1):
    Data = wholefile[35:]
  else:
    Data = wholefile[19:]
    
  if PacketType == 1:
    AnnounceData(Data,HeaderContext)
  elif DestinationType == 3:
    print("### Link data is encrypted ###")
    print("")
  else:
    RawData(Data)
  
def RawData(Data):
  print("### Raw Data ###")
  print("Length: "+str(len(Data)))
  print("Bytes: ")
  print(Data.hex())
  print(" ")
  print("UTF-8: ")# Ignores errors
  print(Data.decode("utf-8",errors="replace"))
  
def AnnounceData(Data,HeaderContext):
  print("### Announce Data ###")
  PubKey = Data[:64]
  NameHash = Data[64:74]
  RandomHash = Data[74:84]
  Signature = Data[84:148]
  if HeaderContext == Codes["Ratchet"]:
    Ratchet = Data[148:180]
    AppData = Data[180:]
  else:
    AppData = Data[148:]
  
  print("Public Key:  "+str(PubKey.hex()))
  print("Name Hash:   "+str(NameHash.hex()))
  print("Random Hash: "+str(RandomHash.hex()))
  print("Signature:   "+str(Signature.hex()))
  if HeaderContext == Codes["Ratchet"]:
    print("Ratchet:     "+str(Ratchet.hex()))
  print("Raw AppData: "+str(AppData.hex()))
  print("      UTF-8: "+str(AppData.decode("utf-8",errors="ignore")))
  print("")
  if AppData != None and AppData != b"":
    try:
      message = msgpack.unpackb(AppData)
      print(message)
    except:
      pass

def DumpPacket(path):
  with open(path,'rb') as packet:
    byte = packet.read(1)
    stringbuffer = ""
    while byte:
      stringbuffer+=(byte.hex()+" ")
      byte=packet.read(1)
    print(stringbuffer)
  
filelist = GetDirectory('.')
#ParsePacket(filelist[0])
for f in filelist:
  if "bytes" in f:
    ParsePacket(f)