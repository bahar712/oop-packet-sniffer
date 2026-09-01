from scapy.all import sniff, IP, TCP, UDP
import datetime
from collections import Counter


class PacketInfo:
    def __init__(self,src_ip,dst_ip,protocol,size, timestamp):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.size = size
        self.timestamp = timestamp  

    def __str__(self):
        return f" source IP: {self.src_ip}\n destination IP: {self.dst_ip} \n protocol: {self.protocol} \n size: {self.size} \n time stamp: {self.timestamp}"

class PacketParser:
    @staticmethod
    def parse(packet):
        if TCP in packet: 
                protocol="TCP"
        elif UDP in packet:
                protocol="UDP"
        else:
                protocol="Other"
        size=len(packet)
        timestamp=datetime.datetime.now()
        packet_info = PacketInfo(packet[IP].src,packet[IP].dst, protocol, size,timestamp)
        return packet_info
    
class PacketCapturer:
    def __init__(self,count,prn):
        self.count = count 
        self.prn = prn

    def start(self):
        sniff(count=self.count,prn=self.prn)

class TrafficAnalyzer:
     def __init__(self):
          self.packets = []
          self.ip_counter = Counter()
          self.protocol_counter = Counter()

     def add_packet(self,packet_info):
          self.packets.append(packet_info)
          self.ip_counter[packet_info.src_ip] +=1
          self.protocol_counter[packet_info.protocol] +=1

     def total_packets(self):
        return len(self.packets)

     def top_talkers(self,n=5):
          return self.ip_counter.most_common(n)

     def protocol_distribution(self):
          return dict(self.protocol_counter)

         
def packet_recieved(packet):
    packet_info = PacketParser.parse(packet)
    traffic_analyzer.add_packet(packet_info)

traffic_analyzer = TrafficAnalyzer()

packet_capturer = PacketCapturer(count=5,prn=packet_recieved)
packet_capturer.start()



