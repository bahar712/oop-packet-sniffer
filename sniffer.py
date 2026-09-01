from scapy.all import sniff, IP, TCP, UDP
import datetime


class PacketInfo:
    def __init__(self,src_ip,dst_ip,protocol,size, timestamp):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.size = size
        self.timestamp = timestamp  

    def __str__(self):
        return f" source IP: {self.src_ip}\n destination IP: {self.dst_ip} \n protocol: {self.protocol} \n size: {self.size} \n time stamp: {self.timestamp}"

def packet_recieved(packet):
    if TCP in packet: 
        protocol="TCP"
    elif UDP in packet:
        protocol="UDP"
    else:
        protocol="Diğer"
    size=len(packet)
    timestamp=datetime.datetime.now()
    packet_info = PacketInfo(packet[IP].src,packet[IP].dst, protocol, size,timestamp)
    print(packet_info)

sonuc = sniff(count=1, prn=packet_recieved)