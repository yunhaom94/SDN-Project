import dpkt
import socket
from datetime import datetime
import operator


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
        self.controller = Controller()
        self.current_time = 0
        self.dump_interval = 100 # hardcode to 10ms right now
        # last time statistic dump time
        # also used for check for timeout
        self.last_dump_time = 0 
        self.total_packets = 0

    # process an IP packet
    def process_packet(self, timestamp, raw_packet):
        #print("---------Processing Packet At Time:----------")
        #print(datetime.utcfromtimestamp(timestamp))
        self.current_time = timestamp
        self.total_packets += 1


        if (self.current_time - self.last_dump_time) * 1000 > self.dump_interval:
            self.flow_table.all_timeout(self.current_time)
            self.output_statistics()
            self.last_dump_time = self.current_time

        eth = dpkt.ethernet.Ethernet(raw_packet)
        ip = eth.data

        if not isinstance(ip, dpkt.ip.IP):
            #print("Not an IP packet")
            return

        tcp = ip.data

        if not isinstance(tcp, dpkt.tcp.TCP):
            #print("Not an TCP packet")
            return

        packet = Packet(timestamp)

        packet.eth_src = eth.src
        packet.eth_dst = eth.dst
        packet.eth_type = eth.type

        packet.ip_src = ip.src
        packet.ip_dst = ip.dst
        packet.ip_protocol = ip.p

        packet.tcp_sport = tcp.sport
        packet.tcp_dport = tcp.dport
        
        #packet.print_packet()

        id = packet.get_id()

        if self.flow_table.if_flow_exists(id):
            self.flow_table.update_flow(packet)
        else:
            flow = self.controller.create_flow(packet)
            self.flow_table.insert_flow(flow)

    def output_statistics(self):
        print("Current Time is: " + str(datetime.utcfromtimestamp(self.current_time)))
        print("Number of Packets Processed: "+ str(self.total_packets))
        print("Timeout Set to: " + str(self.flow_table.timeout))
        print("Current Active Flow: " + str(self.flow_table.current_active_flow))
        print("Total Number of Flows Installed: " + str(self.flow_table.total_flow))
        print("Maximum Number of Active Flows: " + str(self.flow_table.max_flow_count))
        print("Maximum Number of Packets in Active Flow: " + str(self.flow_table.get_max_packets_flow()))

        print("======================================================")



class FlowTable:
    def __init__(self):
        self.table = {}
        self.timeout = 100
        # statistics figures
        self.timeout_flow_count = 0
        self.max_flow_count = 0
        self.current_active_flow = 0
        self.total_flow = 0

    def if_flow_exists(self, flow_id):
        if flow_id in self.table:
            return True
        else:
            return False

    def insert_flow(self, flow):
        if self.if_flow_exists(flow.id):
            raise Exception("Flow already exists")

        self.table[flow.id] = flow
        self.total_flow += 1
        self.current_active_flow += 1
        if self.current_active_flow > self.max_flow_count:
            self.max_flow_count = self.current_active_flow

    def delete_flow(self, id):
        if not self.if_flow_exists(id):
            raise Exception("Flow does not exist")
        
        del self.table[id]
        self.current_active_flow -= 1

    def update_flow(self, packet):
        id = packet.get_id()
        if not self.if_flow_exists(id):
            raise Exception("Flow does not exist")

        flow = self.table[id]
        flow.packets_count += 1
        flow.last_update = packet.timestamp
        self.table[id] = flow

    def check_timeout(self, flow, current_time):
        """
        Iterate through the table and check for timeout
        """

        # convert to ms
        delta = (current_time - flow.last_update) * 1000
        if delta > self.timeout:
            return True
        else:
            return False
    
    def all_timeout(self, current_time):
        to_delete = []

        for id, flow in self.table.items():
            if self.check_timeout(flow, current_time):
                to_delete.append(id)

        for id in to_delete:
            self.delete_flow(id)

    def get_max_packets_flow(self):
        
        if len(self.table.values()) > 0:
            return max(self.table.values(), key=operator.attrgetter("packets_count")).packets_count
        else:
            return 0


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
        self.eth_dst = None
        self.eth_type = None
        self.ip_src = None
        self.ip_dst = None
        self.ip_protocol = None
        self.tcp_sport = None
        self.tcp_dport = None
        self.size = 0
    
    def get_id(self):
        return "" + str(self.ip_src) + str(self.ip_dst) + str(self.tcp_sport) + str(self.tcp_dport)

    def print_packet(self):
        print("Packet with ID: " + self.get_id())
        print("Source MAC: " + mac_addr(self.eth_src))
        print("Dest Mac: " + mac_addr(self.eth_dst))
        print("Source IP: " + inet_to_str(self.ip_src))
        print("Dest IP: " + inet_to_str(self.ip_dst))
        print("Protocol: " + str(self.ip_protocol))
        # if TCP: ...
        print("TCP Source port: " + str(self.tcp_sport))
        print("TCP Dest port: " + str(self.tcp_dport))


        
class Controller:
    def create_flow(self, packet):
        id = packet.get_id()
        flow = Flow(id)
        flow.packets_count += 1
        flow.first_seen = packet.timestamp
        flow.last_update = flow.first_seen
        flow.active = True
        
        return flow

