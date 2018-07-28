import dpkt
import socket
from datetime import datetime
import operator
from helpers import Output
import random
import collections

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
    def __init__(self, id, timeout, to_file, **kwargs):
        self.id = id
        print("Running Switch: " + self.id)
        self.current_time = 0
        # should be same as timeout if it's less than 100
        self.dump_interval = timeout if timeout < 100 else 100 
        # last time statistic dump time
        # also used for check for timeout
        self.last_dump_time = 0 
        self.total_packets = 0
        self.first_write = True # used to check for writing logs to file
        self.missed = 0 # # of packets that needs to create a new flow for it
        self.output_to_file = to_file

        self.flow_table = BaseFlowTable(timeout) # default flow table
        if "rule" in kwargs.keys():
            rule = kwargs["rule"]
            if rule == "two_level_random":
                self.flow_table = TwoLevelFlowTable(timeout, 1)

            elif rule == "two_level_fifo":
                self.flow_table = TwoLevelFlowTable(timeout, 2)
                

    def process_packet(self, timestamp, raw_packet):
        '''
        Process an IP packet and output statstics
        '''
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
        packet.size = len(raw_packet)

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
            Output.VERBOSE("Not TCP or UDP")
            return


        if tcp and type(tcp) == dpkt.tcp.TCP:
            packet.sport = tcp.sport
            packet.dport = tcp.dport
        elif udp and type(udp) == dpkt.udp.UDP:
            packet.sport = udp.sport
            packet.dport = udp.dport
        else:
            return
        

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


    def output_all_flow(self, to_file=True):
        self.flow_table.output_all_flow(self.id, to_file)


class BaseFlowTable:
    '''
    Most basic flow table
    With 1 dictionary and fixed timeout
    '''
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
        ''' 
        Handles cases where a flow already exists.
        If it's active, update the last rule in rule list.
        If it's not active, a new rule needs to be created.
        '''
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
        latest_rule.new_packet(packet)
        
        self.table[id] = flow

        if self.current_active_flow > self.max_flow_count:
            self.max_flow_count = self.current_active_flow


    def non_existing_flow(self, packet):
        '''
        Handles cases where a flow DNE.
        Create a new flow and added to flow table then
        call the existing flow handler
        '''

        id = packet.get_id()
        if self.if_flow_exists(id):
            raise Exception("Flow exists")

        self.table[id] = self.create_flow(packet)
        self.existing_flow(packet)
        self.total_flows += 1


    def deactivate_flow(self, id):
        '''
        Set a flow as deactivated, decrement the active flow counter
        
        '''
        if not self.if_flow_exists(id):
            raise Exception("Flow does not exist")
        
        self.table[id].deactivate_flow()
        self.current_active_flow -= 1

    def check_timeout(self, flow, current_time):
        # converts to ms
        delta = (current_time - flow.last_update) * 1000
        if delta > self.timeout:
            Output.DEBUG("Timing out " + flow.id)
            return True
        else:
            return False
    
    def all_timeout(self, current_time):
        """
        Iterates through the flow table and checks for timeout.
        """
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
        flow = Flow(id, packet.ip_src, packet.ip_dst, packet.ip_protocol,
                    packet.sport, packet.dport, packet.timestamp)

        flow.deactivate_flow()
        
        return flow

    def output_all_flow(self, switch_id, to_file):
        out_str = ""

        for id, flow in self.table.items():
            
            flow_stats = \
'''
Total number of Rules: {num_rules}
Total backets: {packets_count}
Total bytes: {byte_count}
Flow Hit Rate: {hit_rate}
*
            '''.format(num_rules=len(flow.rules),
            hit_rate=flow.get_hit_rate(),
            packets_count=flow.get_packet_count(),
            byte_count=flow.get_byte_count())

            out_str += (flow.output_info() + flow_stats)

        if to_file:
            filename = "log_flow_" + str(switch_id)            
            with open(filename, "w+")  as out_file:
                out_file.write(out_str)
                out_file.close()
        
        else:
            print(out_str)

class TwoLevelFlowTable(BaseFlowTable):
    def __init__(self, timeout, eviction_policy, secondary_table_size=10):
        super().__init__(timeout)
        self.secondary_table = collections.OrderedDict()
        self.secondary_table_size = secondary_table_size
        self.secondary_table_occupancy = 0
        # this should be able to modify easily
                        
        if eviction_policy == 1:
            print("Using two_level_random rule")
            self.eviction_policy = self.random_eviction
        if eviction_policy == 2:
            print("Using two_level_fifo rule")
            self.eviction_policy = self.FIFO
        else:
            print("Using two_level_random rule")
            self.eviction_policy = self.random_eviction

    def deactivate_flow(self, id):
        super().deactivate_flow(id)
        self.push_secondary(id) # push to secondary table


    def non_existing_flow(self, packet):
        '''
        Handles cases where a flow DNE.
        Create a new flow and added to flow table then
        call the existing flow handler
        '''

        id = packet.get_id()
        if self.if_flow_exists(id):
            raise Exception("Flow exists")

        if self.if_secondary_exists(id):
            flow = self.secondary_table[id]
            self.table[id] = flow
            flow.active = True
            self.existing_flow(packet)

        else:
            super().non_existing_flow(packet)
        

    def if_secondary_exists(self, id):
        if id in self.secondary_table.keys():
            return True
        else:
            return False


    def push_secondary(self, id):
        if self.secondary_table_occupancy > self.secondary_table_size:
            self.eviction_policy()

        self.secondary_table[id] = self.table[id]
        self.secondary_table_occupancy += 1


        
    def random_eviction(self):
        evicted = random.choice(list(self.secondary_table))
        del self.secondary_table[evicted]
        self.secondary_table_occupancy -= 1


    def FIFO(self):
        self.secondary_table.popitem(last=False)
        self.secondary_table_occupancy -= 1


    # TODO: add more eviction methods


class Flow:
    def __init__(self, id, ip_src, ip_dst, ip_protocol, sport, dport, cur_time):
        self.id = id # Rule, souce_ip + ip_dst + portocol + sport + dport
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_protocol = ip_protocol
        self.sport = sport
        self.dport = dport
        self.last_update = cur_time
        self.active = True # if timeout, mark inactive
        self.rules = []

    def deactivate_flow(self):
        self.active = False

    def create_rule(self, create_time):
        rule = Rule(create_time)
        self.rules.append(rule)

        return rule

    def get_packet_count(self):
        total = 0
        for r in self.rules:
            total += r.packets_count

        return total

    def get_byte_count(self):
        total = 0

        for r in self.rules:
            total += r.byte_count

        return total

    def get_hit_rate(self):
        '''Get hit rate of individual flow'''

        # only when a packet missed, an rule will be added
        missed = len(self.rules)
        packets_count = self.get_packet_count()

        return float((packets_count - missed) / packets_count)

    def output_info(self):
        '''return a string of self's info'''
        if self.ip_protocol == IP_PROTOCOL.TCP:
            portocol = "TCP" 
        elif self.ip_protocol == IP_PROTOCOL.UDP:
            portocol = "UDP"
            
        out_str = '''
Flow id: {flow_id}
Source IP: {ip_src}
Dest IP: {dest_ip}
IP portocol: {portocol}
Src port: {sport}
Dest port: {dport}
            '''.format(flow_id=self.id,
            ip_src=inet_to_str(self.ip_src),
            dest_ip=inet_to_str(self.ip_dst),
            portocol=portocol,
            sport=self.sport,
            dport=self.dport)

        return out_str
        

class Rule:
    def __init__(self, first_seen):
        self.packets_count = 0
        self.byte_count = 0
        self.first_seen = first_seen  
        self.last_update = None

    def new_packet(self, packet):
        self.last_update = packet.timestamp
        self.packets_count += 1
        self.byte_count += packet.size


class Packet:
    def __init__(self, timestamp):
        self.timestamp = timestamp
        self.eth_src = None
        self.eth_dst = None
        self.eth_type = None
        self.ip_src = None
        self.ip_dst = None
        self.ip_protocol = None
        self.sport = None
        self.dport = None

        self.size = 0
        #Output.DEBUG(func=self.print_packet)
    
    def get_id(self):

        return "" + str(self.ip_src) + str(self.ip_dst) + \
                  str(self.ip_protocol) + str(self.sport) + str(self.dport)
    
    def print_packet(self):
        print("Packet with ID: " + self.get_id())
        print("Source MAC: " + mac_addr(self.eth_src))
        print("Dest Mac: " + mac_addr(self.eth_dst))
        print("Source IP: " + inet_to_str(self.ip_src))
        print("Dest IP: " + inet_to_str(self.ip_dst))
        print("Protocol: " + str(self.ip_protocol))
        print("Source port: " + str(self.sport))
        print("Dest port: " + str(self.dport))

