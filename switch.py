import dpkt
import socket
from datetime import datetime


#### HELPER FUNCTIONS FROM 
#### http://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html#mac_addr
#### With modification
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    result = ""
    for b in address:
        result += ':' + '%02x' % dpkt.compat.compat_ord(b)
    return result[1:]



def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

""" 
class Packet:
    def __init__(self):
        self.eth_src = None
        self.eth_dest = None
        self.eth_type = None
        self.ip_src = None
        self.ip_dest = None
        self.ip_type = None
 """

# the class to simulate a switch
class Switch:
    def __init__(self):
        self.id = None
        self.flow_table = FlowTable()

    # process an IP packet
    def process_packet(self, timestamp, raw_packet):
        print("---------Processing Packet At Time:----------")
        print(datetime.utcfromtimestamp(timestamp))

        eth = dpkt.ethernet.Ethernet(raw_packet)
        ip = eth.data

        if not isinstance(ip, dpkt.ip.IP):
            print("Not an IP packet")
            return

        tcp = ip.data

        if not isinstance(tcp, dpkt.tcp.TCP):
            print("Not an TCP packet")
            return

        packet = Packet(timestamp)

        packet.eth_src = eth.src
        packet.eth_dst = eth.dst
        packet.eth_type = eth_type

        packet.ip_src = inet_to_str(ip.src)
        packet.ip_dst = inet_to_str(ip.dst)
        packet.ip_protocol = ip.p

        packet.tcp_sort = tcp.sport
        packet.tcp_dport = tcp.dport
        
        packet.print_packet()
        

        


class FlowTable:
    def __init__(self):
        self.table = {}
        self.timeout = None

    def if_flow_exists(self, id):
        if id in self.table
            return True
        else:
            return False

    def insert_flow(self, flow):
        if self.if_flow_exists(flow.id):
            raise Exception("Flow already exists")

        self.table[flow.key] = flow

    def deactivate_flow(self, id):
        if not self.if_flow_exists(id):
            raise Exception("Flow does not exist")
        
        self.table[id].active = False

        return

    def check_timeout(self, flow, timeout=self.timeout):
        """
        Iterate through the table and check for timeout
        """

        delta = time.time() - flow.last_update # TODO: fix this. not current time
        if delta > timeout:
            return True
        else:
            return False
        


class Flow:
    def __init__(self, id):
        self.id = id # Rule, souce_ip + dst_ip + src_port + dst_port
        self.packets_count = 0
        self.byte_count = 0
        self.first_seen = None
        self.last_update = None
        self.active = True # if timeout, mark inactive


class Packet:
    def __init__(self, timestamp):
        self.timestamp = timestamp
        self.eth_src = None
        self.eth_dest = None
        self.eth_type = None
        self.ip_src = None
        self.ip_dst = None
        self.ip_protocol = None
        self.tcp_sport = None
        self.tcp_dport = None
    
    def get_id(self):
        return str(self.ip_src) + str(self.ip_dst) + str(self.tcp_src_port) + str(self.tcp_dst_port)

    def print_packet(self)
        print("Packet with ID: ") + self.get_id()
        print("Source MAC: ") + self.eth_src
        print("Dest Mac: ") + self.eth_dest
        print("Source IP: ") + self.ip_src
        print("Dest IP: ") + self.ip_dst
        print("Protocol: ") + self.ip_protocol
        # if TCP: ...
        print("TCP Source port: ") + self.tcp_sport
        print("TCP Dest port: ") + self.tcp_dport


        



class Controller:
    def create_flow(self, packet):
        id = packet.get_id()
        flow = Flow(id)
        flow.packets_count += 1
        flow.first_seen = packet.timestamp
        flow.last_update = flow.first_seen
        flow.active = True
        
        return flow