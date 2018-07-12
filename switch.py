import dpkt
import socket
from datetime import datetime
import operator
from helpers import Output

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

#### MORE HELPERS
class IP_PROTOCOL():
    ICMP = 1
    TCP = 6
    UDP = 17
    

# the class to simulate a switch
class Switch:
    def __init__(self, id, timeout, to_file):
        self.id = id
        self.flow_table = FlowTable(timeout)
        self.current_time = 0
        self.dump_interval = timeout # should be same as timeout
        # last time statistic dump time
        # also used for check for timeout
        self.last_dump_time = 0 
        self.total_packets = 0
        self.first_write = True # used to check for writing logs to file
        self.missed = 0 # # of packets that needs to create a new flow for it
        self.output_to_file = to_file

    # process an IP packet
    def process_packet(self, timestamp, raw_packet):
        Output.VERBOSE("---------Processing Packet At Time:----------")
        Output.VERBOSE(datetime.utcfromtimestamp(timestamp))
        self.current_time = timestamp
        self.total_packets += 1


        if (self.current_time - self.last_dump_time) * 1000 > self.dump_interval:
            self.flow_table.all_timeout(self.current_time)
            self.output_statistics(self.output_to_file)
            self.last_dump_time = self.current_time

        try:
            eth = dpkt.ethernet.Ethernet(raw_packet)
        except Exception:
            return
        
        ip = eth.data

        if not isinstance(ip, dpkt.ip.IP):
            Output.VERBOSE("Not an IP packet")
            return

        packet = Packet(timestamp)

        packet.eth_src = eth.src
        packet.eth_dst = eth.dst
        packet.eth_type = eth.type

        packet.ip_src = ip.src
        packet.ip_dst = ip.dst
        packet.ip_protocol = ip.p

        tcp, udp = None, None

        if packet.ip_protocol == IP_PROTOCOL.TCP: # tcp
            tcp = ip.data
        elif packet.ip_protocol == IP_PROTOCOL.UDP: # udp
            udp =  ip.data
        else:
            return


        if tcp and type(tcp) == dpkt.tcp.TCP:
            packet.tcp_sport = tcp.sport
            packet.tcp_dport = tcp.dport
        elif udp and type(udp) == dpkt.udp.UDP:
            packet.udp_dport = udp.dport
            packet.udp_sport = udp.dport
        else:
            Output.VERBOSE("Not TCP or UDP")
            return
        
        #packet.print_packet()

        id = packet.get_id()

        if self.flow_table.if_flow_exists(id):
            self.flow_table.existing_flow(packet)
        else:
            self.flow_table.non_existing_flow(packet)

    def output_statistics(self, to_file):

        hit_ratio = float((self.total_packets - self.flow_table.missed) / self.total_packets)

        output_str = '''
Current Time is: {time}
Total Number of Packets Processed: {total_packet}
Timeout Set to: {timeout}
Currently Active Flows: {active_flow}
Maximum Number of Packets In Active Flows: {max_packets}
Maximum Number of Bytes In Active Flows: {max_bytes}
Total Number of Rules Ever Installed: {total_rules}
Overall Hit Ratio: {hit_ratio}
Maximum Number of Installed Rules At a Time: {max_flow_count}
*
        '''.format(time=str(datetime.utcfromtimestamp(self.current_time)),\
        total_packet=str(self.total_packets),\
        timeout=str(self.flow_table.timeout),\
        active_flow=str(self.flow_table.current_active_flow),\
        total_rules=str(self.flow_table.total_rules),\
        max_flow_count=str(self.flow_table.max_flow_count),\
        max_packets=str(self.flow_table.get_max_packets_flow()),\
        max_bytes="TODO",\
        hit_ratio=hit_ratio)
        
        if to_file:
            filename = "log_" + str(self.id)
            # create a file if first time writing to file
            if self.first_write: 
                outfile = open(filename, "w+") # create or overwrite the file
                outfile.close()
                self.first_write = False

            with open(filename, "a") as out_file:
                out_file.write(output_str)


        else:
            print(output_str)




class FlowTable:
    def __init__(self, timeout):
        self.table = {}
        self.timeout = timeout
        # statistics figures
        self.timeout_flow_count = 0
        self.max_flow_count = 0
        self.current_active_flow = 0
        self.total_flows = 0
        self.total_rules = 0
        self.missed = 0

    def if_flow_exists(self, id):
        if id in self.table.keys():
            return True
        else:
            return False

    def existing_flow(self, packet):
        id = packet.get_id()
        if not self.if_flow_exists(id):
            raise Exception("Flow does not exist")

        flow = self.table[id]
        latest_rule = None

        if flow.active:
            latest_rule = flow.rules[-1]
        else:
            latest_rule = flow.create_rule(packet.timestamp)
            self.missed += 1
            self.total_rules += 1
            self.current_active_flow += 1
            flow.active = True
            Output.DEBUG("Added new rule")

        flow.last_update = packet.timestamp
        latest_rule.last_update = packet.timestamp
        latest_rule.packets_count += 1
        
        self.table[id] = flow


    def non_existing_flow(self, packet):
        id = packet.get_id()
        if self.if_flow_exists(id):
            raise Exception("Flow exists")

        self.table[id] = self.create_flow(packet)
        self.existing_flow(packet)
        self.total_flows += 1


    def deactivate_flow(self, id):
        if not self.if_flow_exists(id):
            raise Exception("Flow does not exist")
        
        self.table[id].active = False
        self.current_active_flow -= 1

    def check_timeout(self, flow, current_time):
        """
        Iterate through the table and check for timeout
        """

        # converts to ms
        delta = (current_time - flow.last_update) * 1000
        if delta > self.timeout:
            Output.DEBUG("Timing out " + flow.id)
            return True
        else:
            return False
    
    def all_timeout(self, current_time):
        expired = []

        for id, flow in self.table.items():
            if flow.active and self.check_timeout(flow, current_time):
                expired.append(id)

        for id in expired:
            self.deactivate_flow(id)

    def get_max_packets_flow(self):
        
        if len(self.table.values()) > 0:
            max_flow = max(self.table.values(), key=lambda x : x.rules[-1].packets_count)
            return max_flow.rules[-1].packets_count
        else:
            return 0


    def create_flow(self, packet):
        id = packet.get_id()
        flow = Flow(id)
        flow.last_update = packet.timestamp
        flow.active = False
        
        return flow





class Flow:
    def __init__(self, id):
        self.id = id # Rule, souce_ip + dst_ip + src_port + dst_port
        self.last_update = None
        self.active = True # if timeout, mark inactive
        self.rules = []

    def create_rule(self, create_time):
        rule = Rule(create_time)
        self.rules.append(rule)

        return rule
        

class Rule:
    def __init__(self, first_seen):
        self.packets_count = 0
        self.byte_count = 0
        self.first_seen = first_seen  
        self.last_update = None

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
        self.udp_sport = None
        self.udp_dport = None
        self.size = 0
        #Output.DEBUG(func=self.print_packet)
    
    def get_id(self):
        ports = ""
        if self.ip_protocol == IP_PROTOCOL.TCP:
            ports = str(self.tcp_sport) + str(self.tcp_dport)
        elif self.ip_protocol == IP_PROTOCOL.UDP:
            ports = str(self.udp_dport) + str(self.udp_sport)

        return "" + str(self.ip_src) + str(self.ip_dst) + ports
    
    def print_packet(self):
        print("Packet with ID: " + self.get_id())
        print("Source MAC: " + mac_addr(self.eth_src))
        print("Dest Mac: " + mac_addr(self.eth_dst))
        print("Source IP: " + inet_to_str(self.ip_src))
        print("Dest IP: " + inet_to_str(self.ip_dst))
        print("Protocol: " + str(self.ip_protocol))
        print("TCP Source port: " + str(self.tcp_sport))
        print("TCP Dest port: " + str(self.tcp_dport))


