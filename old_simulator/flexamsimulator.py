#!/usr/bin/python

import dpkt
import sys
import collections
import random
import multiprocessing
import time
import struct
import math

INFINITE_TIME = 999999999999999
EPSILON = 0.01

# The multiplier to convert idle timeout form seconds to microseconds
IDLE_TIMEOUT_CONSTANT_MULTIPLER = 1000

class SamplingConfig():
    sampling_rho = 0
    sampling_delta = 0
    sampling_m = 1
    sampling_k = 1
    sampling_alpha = 4

class Config():
    catchall_sampling = SamplingConfig()
    installed_rule_sampling = SamplingConfig()

    installed_rule_sampling.sampling_rho = 0
    installed_rule_sampling.sampling_delta = 0
    installed_rule_sampling.sampling_m = 1
    installed_rule_sampling.sampling_k = 1
    installed_rule_sampling.sampling_alpha = 2

    catchall_sampling.sampling_rho = 0
    catchall_sampling.sampling_delta = 0
    catchall_sampling.sampling_m = 1
    catchall_sampling.sampling_k = 4

    install_rule_sample_threshold = 3
    maximum_flow_idle_time = 90

    verbose_level = 6
    prone_all_flows_info_interval = 100000
    end_of_world_timestamp = INFINITE_TIME

    log_directory = "./"
    log_file_prefix = "log"
    log_file_id = None
    log_file_extension = ".txt"
    log_file_name = None
    log_file = None
    log_sampled_packet_size = False
    log_sampled_packet_tcp_flag = False
    log_sampled_packet_tcp_sqn = False
    log_sampled_packet_interarrival_time = False

    all_flows_info = {}
    catchall_flow = None
    catchall_flow_installed_rule = None
    config_id = ""

    idle_timeout_increasing_only = True

    def __init__(self, common=None, id=None):
        self.catchall_sampling = SamplingConfig()
        self.installed_rule_sampling = SamplingConfig()

        self.installed_rule_sampling.sampling_rho = 0
        self.installed_rule_sampling.sampling_delta = 0
        self.installed_rule_sampling.sampling_m = 1
        self.installed_rule_sampling.sampling_k = 1
        self.installed_rule_sampling.sampling_alpha = 2

        self.catchall_sampling.sampling_rho = 0
        self.catchall_sampling.sampling_delta = 0
        self.catchall_sampling.sampling_m = 1
        self.catchall_sampling.sampling_k = 4

        self.install_rule_sample_threshold = 3
        self.maximum_flow_idle_time = 90

        self.verbose_level = 6
        self.prone_all_flows_info_interval = 100000
        self.end_of_world_timestamp = INFINITE_TIME

        self.log_directory = "./"
        self.log_file_prefix = "log"
        self.log_file_id = None
        self.log_file_extension = ".txt"
        self.log_file_name = None
        self.log_file = None
        self.log_sampled_packet_size = False
        self.log_sampled_packet_interarrival_time = False
        self.log_sampled_packet_tcp_flag = False
        self.log_sampled_packet_tcp_sqn = False

        self.all_flows_info = {}
        self.catchall_flow = None
        self.catchall_flow_installed_rule = None
        self.config_id = id

        self.idle_timeout_increasing_only = True

        self.GeneratePacketID = GeneratePacketIDLowerPort

        self.ProcessPacket = ProcessPacketDynamicHHDetection
        self.ProcessSampledPacket = ProcessSampledPacketDynamicHHDetection
        self.UpdateIdleTimeout = UpdateIdleTimeoutUnchanged
        self.SetInitialIdleTimeout = SetInitialIdleTimeoutConstant

        self.EvictRule = EvictRuleLRU

        self.show_statistics_interval = 60
        self.last_time_shown_statistics = -1
        self.ShowStatistics = ShowStatisticsNothing

        self.installed_flows = {}

        self.rule_install_delay = 0
        self.rule_install_delay_first = 0
        self.rule_timeout_idle_beta = 1
        self.rule_timeout_hard_gamma = 1
        self.rule_timeout_idle_zeta = 1
        self.rule_timeout_idle_theta = 1
        self.rule_timeout_idle = INFINITE_TIME
        self.rule_timeout_hard = INFINITE_TIME
        self.rule_timeout_idle_min = 0
        self.rule_timeout_idle_max = INFINITE_TIME

        self.flow_table_maximum_size = INFINITE_TIME

        if common:
            # Copy values from the common config
            self.installed_rule_sampling.sampling_rho = common.installed_rule_sampling.sampling_rho
            self.installed_rule_sampling.sampling_delta = common.installed_rule_sampling.sampling_delta
            self.installed_rule_sampling.sampling_m = common.installed_rule_sampling.sampling_m
            self.installed_rule_sampling.sampling_k = common.installed_rule_sampling.sampling_k
            self.installed_rule_sampling.sampling_alpha = common.installed_rule_sampling.sampling_alpha

            self.catchall_sampling.sampling_rho = common.catchall_sampling.sampling_rho
            self.catchall_sampling.sampling_delta = common.catchall_sampling.sampling_delta
            self.catchall_sampling.sampling_m = common.catchall_sampling.sampling_m
            self.catchall_sampling.sampling_k = common.catchall_sampling.sampling_k

            self.install_rule_sample_threshold = common.install_rule_sample_threshold
            self.maximum_flow_idle_time = common.maximum_flow_idle_time

            self.verbose_level = common.verbose_level
            self.prone_all_flows_info_interval = common.prone_all_flows_info_interval
            self.end_of_world_timestamp = common.end_of_world_timestamp

            self.log_directory = common.log_directory
            self.log_file_prefix = common.log_file_prefix
            self.log_file_id = common.log_file_id
            self.log_file_extension = common.log_file_extension
            self.log_sampled_packet_size = common.log_sampled_packet_size
            self.log_sampled_packet_interarrival_time = common.log_sampled_packet_interarrival_time
            self.log_sampled_packet_tcp_flag = common.log_sampled_packet_tcp_flag
            self.log_sampled_packet_tcp_sqn = common.log_sampled_packet_tcp_sqn

            self.idle_timeout_increasing_only = common.idle_timeout_increasing_only

            self.GeneratePacketID = common.GeneratePacketID

            self.ProcessPacket = common.ProcessPacket
            self.ProcessSampledPacket = common.ProcessSampledPacket
            self.UpdateIdleTimeout = common.UpdateIdleTimeout
            self.SetInitialIdleTimeout = common.SetInitialIdleTimeout

            self.EvictRule = common.EvictRule

            self.show_statistics_interval = common.show_statistics_interval
            self.ShowStatistics = common.ShowStatistics

            self.rule_install_delay = common.rule_install_delay
            self.rule_install_delay_first = common.rule_install_delay_first
            self.rule_timeout_idle_beta = common.rule_timeout_idle_beta
            self.rule_timeout_hard_gamma = common.rule_timeout_hard_gamma
            self.rule_timeout_idle_zeta = common.rule_timeout_idle_zeta
            self.rule_timeout_idle_theta = common.rule_timeout_idle_theta
            self.rule_timeout_idle = common.rule_timeout_idle 
            self.rule_timeout_hard = common.rule_timeout_hard
            self.rule_timeout_idle_min = common.rule_timeout_idle_min
            self.rule_timeout_idle_max = common.rule_timeout_idle_max

            self.flow_table_maximum_size = common.flow_table_maximum_size

class PacketHeader:
    src_ip_1 = None
    src_ip_2 = None
    src_ip_3 = None
    src_ip_4 = None
    dst_ip_1 = None
    dst_ip_2 = None
    dst_ip_3 = None
    dst_ip_4 = None
    src_port = None
    dst_port = None
    protocol = None
    tcp_flags = None
    tcp_sqn = None
    flow_id = None

class PacketInfo(PacketHeader):
    timestamp = None
    packet_length_ip = None
    packet_length_captured = None

class FlowInfo(PacketHeader):
    first_packet_time = -1
    first_packet_time_rule = -1
    first_sampled_packet_time = -1
    last_packet_time = -1
    last_sampled_packet_time = -1
    packet_count = 0
    packet_count_rule = 0
    sampled_packet_count = 0
    flow_byte_sum = 0
    sampled_flow_byte_sum = 0
    rule_installed = False
    rule_command_count = 0
    sampled_packet_sizes = []
    sampled_packet_l4_data_sizes = []
    packet_count_table_miss = 0
    flow_byte_sum_table_miss = 0
    packet_count_table_miss_after_rule = 0
    flow_byte_sum_table_miss_after_rule = 0
    rule_expiry_time = -1
    rule_installed_counter = 0
    packet_interarrival_max = 0
    rule_info = None
    #previous_sampled_packet_time = 0
    previous_sampled_sampling_k = 0
    rule_removal_sampled_packet_count = 0

    def __init__(self, sampling_config = None):
        self.first_packet_time = -1
        self.first_packet_time_rule = -1
        self.first_sampled_packet_time = -1
        self.last_packet_time = -1
        self.last_sampled_packet_time = -1
        self.packet_count = 0
        self.packet_count_rule = 0
        self.sampled_packet_count = 0
        self.flow_byte_sum = 0
        self.sampled_flow_byte_sum = 0
        self.rule_installed = False
        self.rule_command_count = 0
        self.sampled_packet_sizes = []
        self.sampled_packet_l4_data_size = []
        self.sampled_packet_interarrival_times = []
        self.sampled_packet_tcp_flags = []
        self.sampled_packet_tcp_sqn = []
        self.sampled_packet_l4_data_size = []
        self.packet_count_table_miss = 0
        self.flow_byte_sum_table_miss = 0
        self.packet_count_table_miss_after_rule = 0
        self.flow_byte_sum_table_miss_after_rule = 0
        self.rule_expiry_time = -1
        self.rule_installed_counter = 0
        self.packet_interarrival_max = 0
        self.rule_info = None
        #self.previous_sampled_packet_time = 0
        self.previous_sampled_sampling_k = 0
        self.rule_removal_sampled_packet_count = 0

        if sampling_config:
            self.sampling_rho = sampling_config.sampling_rho
            self.sampling_delta = sampling_config.sampling_delta
            self.sampling_m = sampling_config.sampling_m
            self.sampling_k = sampling_config.sampling_k
            self.sampling_alpha = sampling_config.sampling_alpha

    def CopyPacketHeader(self, packet_info):
        self.src_ip_1 = packet_info.src_ip_1
        self.src_ip_2 = packet_info.src_ip_2
        self.src_ip_3 = packet_info.src_ip_3
        self.src_ip_4 = packet_info.src_ip_4
        self.dst_ip_1 = packet_info.dst_ip_1
        self.dst_ip_2 = packet_info.dst_ip_2
        self.dst_ip_3 = packet_info.dst_ip_3
        self.dst_ip_4 = packet_info.dst_ip_4
        self.src_port = packet_info.src_port
        self.dst_port = packet_info.dst_port
        self.protocol = packet_info.protocol
        self.flow_id = packet_info.flow_id

class RuleInfo():
    rule_install_time = -1
    sampling_config = SamplingConfig()
    packet_count = 0
    timeout_idle = INFINITE_TIME
    timeout_hard = INFINITE_TIME
    last_packet_time = -1
    sampled_packet_order_number = -1

    def __init__(self, sampling_config = None):
        self.rule_install_time = -1
        self.sampling_config = SamplingConfig()
        self.packet_count = 0
        self.timeout_idle = INFINITE_TIME
        self.timeout_hard = INFINITE_TIME
        self.last_packet_time = -1
        self.sampled_packet_order_number = -1

        if sampling_config:
            self.sampling_config.sampling_rho = sampling_config.sampling_rho
            self.sampling_config.sampling_delta = sampling_config.sampling_delta
            self.sampling_config.sampling_m = sampling_config.sampling_m
            self.sampling_config.sampling_k = sampling_config.sampling_k
            self.sampling_config.sampling_alpha = sampling_config.sampling_alpha

def GeneratePacketIDWANDISPDataset(ethernet_packet):
    # Generate a packet id from an Ethernet packet
    # Return None in case of a non TCP or UDP packet or any error

    packet_info = PacketInfo()

    # Skip very small packets which are definitely not a TCP or UDP packet
    if (len(ethernet_packet) < 34):
        if (verbose_level >= 13):
            print "A very short packet (len = " + str(len(ethernet_packet)) + \
                  " ) which is definitely not a TCP/UDP packet, so skip it"
        #return (None, 0)
        return packet_info

    (mac_src, mac_dst, ether_type) = struct.unpack('>6s6sH', ethernet_packet[:14])

    # If there is VLAN tag
    if (ether_type == 33024):
        # Skip very small packets which are definitely not a TCP or UDP packet
        if (len(ethernet_packet) < 38):
            if (verbose_level >= 13):
                print "A very short packet (len = " + str(len(ethernet_packet)) + \
                      " , with VLAN tag) which is definitely not a TCP/UDP packet, so skip it"
            #return (None, 0)
            return packet_info
        (ether_type,) = struct.unpack('>H', ethernet_packet[16:18])
        ip_start_index = 18
    else:
        ip_start_index = 14

    # Skip non IPv4 packets
    if (ether_type != 2048):
        #if (verbose_level >= 13):
            #print "A non IPv4 packet (type = " + str(ether_type) + ") seen, so skip it"
            #print "Packet info: " + dpkt.hexdump(ethernet_packet, 42)
            #print "Packet info: " + ':'.join(x.encode('hex') for x in ethernet_packet[:38+4])
            #print "Packet info: " + ':'.join(str(ord(x)) for x in ethernet_packet[:38+4])
        #return (None, 0)
        return packet_info

    (ip_version_header_len, ip_toc, \
     ip_length, ip_id, ip_frag, ttl, protocol, ip_header_checksum, \
     ip_src_1, ip_src_2, ip_src_3, ip_src_4, \
     ip_dst_1, ip_dst_2, ip_dst_3, ip_dst_4) = \
     struct.unpack('>BB' + \
                   'HHHBBH' + \
                   'BBBB' + \
                   'BBBB', \
                   ethernet_packet[ip_start_index:ip_start_index+20])

    # Fragmentation offset if the packet is fragmented
    fragment_offset = ip_frag % 8192

    if (fragment_offset > 0):
        # This is a secondary (not first) part of a fragmented packet, so ignore it
        #if (verbose_level >= 13):
        #    print "A fragmented packet which is not the first part, so skip it"
        #return (None, 0)
        return packet_info

    #if ( (protocol != 6) and (protocol != 17) ):
    #    # For non UDP/TCP packets, set source and destination ports to 0
    #    port_src = 0
    #    port_dst = 0
    #else:
    #    # Otherwise, extract source and destination ports
    #    (port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[ip_start_index+20:ip_start_index+24])

    if (protocol == 6):
        # This is a TCP packet
        (port_src, port_dst, tcp_seq_num_1, tcp_seq_num_2, tcp_ack_num_1, tcp_ack_num_2, tcp_data_offset_res_ns, tcp_flags) = struct.unpack('>HHHHHHBB' , ethernet_packet[ip_start_index+20:ip_start_index+34])
        tcp_sqn = (tcp_seq_num_1 << 16) + tcp_seq_num_2
    elif (protocol == 17):
        # This is a UDP packet
        # Extract source and destination ports
        (port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[ip_start_index+20:ip_start_index+24])
        tcp_flags = -1
        tcp_sqn = -1
    else:
        # For non UDP/TCP packets, set source and destination ports to 0
        port_src = 0
        port_dst = 0
        tcp_flags = -1
        tcp_sqn = -1

    # Generate packet id
    # Check if the source is the residential user
    if ( ( (ip_src_1 == 172) and (ip_src_2 == 141) ) or
         ( (ip_src_1 == 70) and (ip_src_2 == 191) ) ):
        # Source ip is the residential user
        packet_id = str(ip_src_1) + "." + str(ip_src_2) + "." + \
                    str(ip_src_3) + "." + str(ip_src_4) + "_" + str(port_src) + "_" + \
                    str(ip_dst_1) + "." + str(ip_dst_2) + "." + \
                    str(ip_dst_3) + "." + str(ip_dst_4) + "_" + str(port_dst) + "_" + str(protocol)
        packet_info.src_ip_1 = ip_src_1
        packet_info.src_ip_2 = ip_src_2
        packet_info.src_ip_3 = ip_src_3
        packet_info.src_ip_4 = ip_src_4
        packet_info.dst_ip_1 = ip_dst_1
        packet_info.dst_ip_2 = ip_dst_2
        packet_info.dst_ip_3 = ip_dst_3
        packet_info.dst_ip_4 = ip_dst_4
        packet_info.src_port = port_src
        packet_info.dst_port = port_dst

    else:
        # Destination ip is the residential user
        packet_id = str(ip_dst_1) + "." + str(ip_dst_2) + "." + \
                    str(ip_dst_3) + "." + str(ip_dst_4) + "_" + str(port_dst) + "_" + \
                    str(ip_src_1) + "." + str(ip_src_2) + "." + \
                    str(ip_src_3) + "." + str(ip_src_4) + "_" + str(port_src) + "_" + str(protocol)
        packet_info.src_ip_1 = ip_dst_1
        packet_info.src_ip_2 = ip_dst_2
        packet_info.src_ip_3 = ip_dst_3
        packet_info.src_ip_4 = ip_dst_4
        packet_info.dst_ip_1 = ip_src_1
        packet_info.dst_ip_2 = ip_src_2
        packet_info.dst_ip_3 = ip_src_3
        packet_info.dst_ip_4 = ip_src_4
        packet_info.src_port = port_dst
        packet_info.dst_port = port_src

    packet_info.protocol = protocol
    packet_info.tcp_flags = tcp_flags
    packet_info.tcp_sqn = tcp_sqn
    packet_info.flow_id = packet_id
    packet_info.packet_length_ip = ip_length
    packet_info.packet_length_captured = len(ethernet_packet)

    #if (verbose_level >= 15):
    #    print "Packet id is " + packet_id

    return packet_info

def GeneratePacketIDLowerPort(ethernet_packet):
    # Generate a packet id from an Ethernet packet
    # Return None in case of a non TCP or UDP packet or any error

    packet_info = PacketInfo()

    # Skip very small packets which are definitely not a TCP or UDP packet
    if (len(ethernet_packet) < 34):
        if (verbose_level >= 13):
            print "A very short packet (len = " + str(len(ethernet_packet)) + \
                  " ) which is definitely not a TCP/UDP packet, so skip it"
        #return (None, 0)
        return packet_info

    (mac_src, mac_dst, ether_type) = struct.unpack('>6s6sH', ethernet_packet[:14])

    # If there is VLAN tag
    if (ether_type == 33024):
        # Skip very small packets which are definitely not a TCP or UDP packet
        if (len(ethernet_packet) < 38):
            if (verbose_level >= 13):
                print "A very short packet (len = " + str(len(ethernet_packet)) + \
                      " , with VLAN tag) which is definitely not a TCP/UDP packet, so skip it"
            #return (None, 0)
            return packet_info
        (ether_type,) = struct.unpack('>H', ethernet_packet[16:18])
        ip_start_index = 18
    else:
        ip_start_index = 14

    # Skip non IPv4 packets
    if (ether_type != 2048):
        #if (verbose_level >= 13):
            #print "A non IPv4 packet (type = " + str(ether_type) + ") seen, so skip it"
            #print "Packet info: " + dpkt.hexdump(ethernet_packet, 42)
            #print "Packet info: " + ':'.join(x.encode('hex') for x in ethernet_packet[:38+4])
            #print "Packet info: " + ':'.join(str(ord(x)) for x in ethernet_packet[:38+4])
        #return (None, 0)
        return packet_info

    (ip_version_header_len, ip_toc, \
     ip_length, ip_id, ip_frag, ttl, protocol, ip_header_checksum, \
     ip_src_1, ip_src_2, ip_src_3, ip_src_4, \
     ip_dst_1, ip_dst_2, ip_dst_3, ip_dst_4) = \
     struct.unpack('>BB' + \
                   'HHHBBH' + \
                   'BBBB' + \
                   'BBBB', \
                   ethernet_packet[ip_start_index:ip_start_index+20])

    # Fragmentation offset if the packet is fragmented
    fragment_offset = ip_frag % 8192

    if (fragment_offset > 0):
        # This is a secondary (not first) part of a fragmented packet, so ignore it
        #if (verbose_level >= 13):
        #    print "A fragmented packet which is not the first part, so skip it"
        #return (None, 0)
        return packet_info

    #if ( (protocol != 6) and (protocol != 17) ):
    #    # For non UDP/TCP packets, set source and destination ports to 0
    #    port_src = 0
    #    port_dst = 0
    #else:
    #    # Otherwise, extract source and destination ports
    #    (port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[ip_start_index+20:ip_start_index+24])

    if (protocol == 6):
        # This is a TCP packet
        (port_src, port_dst, tcp_seq_num_1, tcp_seq_num_2, tcp_ack_num_1, tcp_ack_num_2, tcp_data_offset_res_ns, tcp_flags) = struct.unpack('>HHHHHHBB' , ethernet_packet[ip_start_index+20:ip_start_index+34])
        tcp_sqn = (tcp_seq_num_1 << 16) + tcp_seq_num_2
    elif (protocol == 17):
        # This is a UDP packet
        # Extract source and destination ports
        (port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[ip_start_index+20:ip_start_index+24])
        tcp_flags = -1
        tcp_sqn = -1
    else:
        # For non UDP/TCP packets, set source and destination ports to 0
        port_src = 0
        port_dst = 0
        tcp_flags = -1
        tcp_sqn = -1

    # Generate packet id
    # Check if the source has higher port number (e.g. is initiating the connection)
    if ( (port_src > port_dst) or ( (port_src == port_dst) and \
                                    ( ((((ip_src_1)*256+ip_src_2)*256+ip_src_3)*256+ip_src_4) > \
                                      ((((ip_dst_1)*256+ip_dst_2)*256+ip_dst_3)*256+ip_dst_4) )) ):
        # Source has higher port number (e.g. is initiating the connection)
        packet_id = str(ip_src_1) + "." + str(ip_src_2) + "." + \
                    str(ip_src_3) + "." + str(ip_src_4) + "_" + str(port_src) + "_" + \
                    str(ip_dst_1) + "." + str(ip_dst_2) + "." + \
                    str(ip_dst_3) + "." + str(ip_dst_4) + "_" + str(port_dst) + "_" + str(protocol)
        packet_info.src_ip_1 = ip_src_1
        packet_info.src_ip_2 = ip_src_2
        packet_info.src_ip_3 = ip_src_3
        packet_info.src_ip_4 = ip_src_4
        packet_info.dst_ip_1 = ip_dst_1
        packet_info.dst_ip_2 = ip_dst_2
        packet_info.dst_ip_3 = ip_dst_3
        packet_info.dst_ip_4 = ip_dst_4
        packet_info.src_port = port_src
        packet_info.dst_port = port_dst

    else:
        # Destination has higher port number (e.g. is initiating the connection)
        packet_id = str(ip_dst_1) + "." + str(ip_dst_2) + "." + \
                    str(ip_dst_3) + "." + str(ip_dst_4) + "_" + str(port_dst) + "_" + \
                    str(ip_src_1) + "." + str(ip_src_2) + "." + \
                    str(ip_src_3) + "." + str(ip_src_4) + "_" + str(port_src) + "_" + str(protocol)
        packet_info.src_ip_1 = ip_dst_1
        packet_info.src_ip_2 = ip_dst_2
        packet_info.src_ip_3 = ip_dst_3
        packet_info.src_ip_4 = ip_dst_4
        packet_info.dst_ip_1 = ip_src_1
        packet_info.dst_ip_2 = ip_src_2
        packet_info.dst_ip_3 = ip_src_3
        packet_info.dst_ip_4 = ip_src_4
        packet_info.src_port = port_dst
        packet_info.dst_port = port_src

    packet_info.protocol = protocol
    packet_info.tcp_flags = tcp_flags
    packet_info.tcp_sqn = tcp_sqn
    packet_info.flow_id = packet_id
    packet_info.packet_length_ip = ip_length
    packet_info.packet_length_captured = len(ethernet_packet)

    #if (verbose_level >= 15):
    #    print "Packet id is " + packet_id

    return packet_info

def GeneratePacketIDAsIs(ethernet_packet):
    # Generate a packet id from an Ethernet packet
    # Return None in case of a non TCP or UDP packet or any error

    packet_info = PacketInfo()

    # Skip very small packets which are definitely not a TCP or UDP packet
    if (len(ethernet_packet) < 34):
        if (verbose_level >= 13):
            print "A very short packet (len = " + str(len(ethernet_packet)) + \
                  " ) which is definitely not a TCP/UDP packet, so skip it"
        #return (None, 0)
        return packet_info

    (mac_src, mac_dst, ether_type) = struct.unpack('>6s6sH', ethernet_packet[:14])

    # If there is VLAN tag
    if (ether_type == 33024):
        # Skip very small packets which are definitely not a TCP or UDP packet
        if (len(ethernet_packet) < 38):
            if (verbose_level >= 13):
                print "A very short packet (len = " + str(len(ethernet_packet)) + \
                      " , with VLAN tag) which is definitely not a TCP/UDP packet, so skip it"
            #return (None, 0)
            return packet_info
        (ether_type,) = struct.unpack('>H', ethernet_packet[16:18])
        ip_start_index = 18
    else:
        ip_start_index = 14

    # Skip non IPv4 packets
    if (ether_type != 2048):
        #if (verbose_level >= 13):
            #print "A non IPv4 packet (type = " + str(ether_type) + ") seen, so skip it"
            #print "Packet info: " + dpkt.hexdump(ethernet_packet, 42)
            #print "Packet info: " + ':'.join(x.encode('hex') for x in ethernet_packet[:38+4])
            #print "Packet info: " + ':'.join(str(ord(x)) for x in ethernet_packet[:38+4])
        #return (None, 0)
        return packet_info

    (ip_version_header_len, ip_toc, \
     ip_length, ip_id, ip_frag, ttl, protocol, ip_header_checksum, \
     ip_src_1, ip_src_2, ip_src_3, ip_src_4, \
     ip_dst_1, ip_dst_2, ip_dst_3, ip_dst_4) = \
     struct.unpack('>BB' + \
                   'HHHBBH' + \
                   'BBBB' + \
                   'BBBB', \
                   ethernet_packet[ip_start_index:ip_start_index+20])

    # Fragmentation offset if the packet is fragmented
    fragment_offset = ip_frag % 8192
    ip_data_length = ip_length - 4 * (ip_version_header_len % 16)

    if (fragment_offset > 0):
        # This is a secondary (not first) part of a fragmented packet, so ignore it
        #if (verbose_level >= 13):
        #    print "A fragmented packet which is not the first part, so skip it"
        #return (None, 0)
        return packet_info

    #if ( (protocol != 6) and (protocol != 17) ):
    #    # For non UDP/TCP packets, set source and destination ports to 0
    #    port_src = 0
    #    port_dst = 0
    #else:
    #    # Otherwise, extract source and destination ports
    #    (port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[ip_start_index+20:ip_start_index+24])

    if (protocol == 6):
        # This is a TCP packet
        (port_src, port_dst, tcp_seq_num_1, tcp_seq_num_2, tcp_ack_num_1, tcp_ack_num_2, tcp_data_offset_res_ns, tcp_flags) = struct.unpack('>HHHHHHBB' , ethernet_packet[ip_start_index+20:ip_start_index+34])
        tcp_sqn = (tcp_seq_num_1 << 16) + tcp_seq_num_2
        #tcp_header_length = 4 * tcp_data_offset_res_ns
        tcp_header_length = tcp_data_offset_res_ns >> 2
        #print "tcp_data_offset_res_ns =", tcp_data_offset_res_ns, "\ttcp_header_length =", tcp_header_length
    elif (protocol == 17):
        # This is a UDP packet
        # Extract source and destination ports
        #(port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[ip_start_index+20:ip_start_index+24])
        (port_src, port_dst, udp_length) = struct.unpack('>HHH' , ethernet_packet[ip_start_index+20:ip_start_index+26])
        #tcp_flags = -1
        #tcp_sqn = -1
    else:
        # For non UDP/TCP packets, set source and destination ports to 0
        port_src = 0
        port_dst = 0
        #tcp_flags = -1
        #tcp_sqn = -1

    # Generate packet id
    packet_info.src_ip_1 = ip_src_1
    packet_info.src_ip_2 = ip_src_2
    packet_info.src_ip_3 = ip_src_3
    packet_info.src_ip_4 = ip_src_4
    packet_info.dst_ip_1 = ip_dst_1
    packet_info.dst_ip_2 = ip_dst_2
    packet_info.dst_ip_3 = ip_dst_3
    packet_info.dst_ip_4 = ip_dst_4
    packet_info.src_port = port_src
    packet_info.dst_port = port_dst
    packet_info.flow_id = str(ip_src_1) + "." + str(ip_src_2) + "." + \
                          str(ip_src_3) + "." + str(ip_src_4) + "_" + str(port_src) + "_" + \
                          str(ip_dst_1) + "." + str(ip_dst_2) + "." + \
                          str(ip_dst_3) + "." + str(ip_dst_4) + "_" + str(port_dst) + "_" + str(protocol)
    packet_info.ip_data_length = ip_data_length

    #print "flow_id =", packet_info.flow_id

    packet_info.protocol = protocol
    if (protocol == 6):
        # This is a TCP packet
        packet_info.tcp_flags = tcp_flags
        packet_info.tcp_sqn = tcp_sqn
        packet_info.tcp_header_length = tcp_header_length
        packet_info.l4_data_size = ip_data_length - tcp_header_length
        #print "ip_data_length =", ip_data_length, "    \ttcp_header_length =", tcp_header_length, "\tl4_data_size =", packet_info.l4_data_size
    elif (protocol == 17):
        # This is a UDP packet
        packet_info.udp_length = udp_length
        #packet_info.l4_data_size = udp_length - 8
        packet_info.l4_data_size = ip_data_length - 8
        #print "ip_data_length =", ip_data_length, "\tudp_length =", udp_length, "\tl4_data_size =", packet_info.l4_data_size

    packet_info.packet_length_ip = ip_length
    packet_info.packet_length_captured = len(ethernet_packet)

    #if (verbose_level >= 15):
    #    print "Packet id is " + packet_id

    return packet_info

def GeneratePacketIDAsIsRaw(ethernet_packet):
    # Generate a packet id from a raw captured packet that only includes IP and TCP/UDP header
    # Return None in case of a non TCP or UDP packet or any error

    packet_info = PacketInfo()

    (ip_version_header_len, ip_toc, \
     ip_length, ip_id, ip_frag, ttl, protocol, ip_header_checksum, \
     ip_src_1, ip_src_2, ip_src_3, ip_src_4, \
     ip_dst_1, ip_dst_2, ip_dst_3, ip_dst_4) = \
     struct.unpack('>BB' + \
                   'HHHBBH' + \
                   'BBBB' + \
                   'BBBB', \
                   ethernet_packet[0:20])

    #print "IP version is " + str(ip_version_header_len >> 4)
    # Skip non IPv4 packets
    if ((ip_version_header_len >> 4) != 4):
        #if (verbose_level >= 13):
            #print "A non IPv4 packet (type = " + str(ether_type) + ") seen, so skip it"
            #print "Packet info: " + dpkt.hexdump(ethernet_packet, 42)
            #print "Packet info: " + ':'.join(x.encode('hex') for x in ethernet_packet[:38+4])
            #print "Packet info: " + ':'.join(str(ord(x)) for x in ethernet_packet[:38+4])
        #header_show = min(len(ethernet_packet), 42)
        #print "A non IPv4 packet (ip_version = " + str(ip_version_header_len >> 4) + ") seen, so skip it"
        #print "Packet info: " + dpkt.hexdump(ethernet_packet, header_show)
        #print "Packet info: " + ':'.join(x.encode('hex') for x in ethernet_packet[:header_show])
        #print "Packet info: " + ':'.join(str(ord(x)) for x in ethernet_packet[:header_show])
        #return (None, 0)
        return packet_info

    # Fragmentation offset if the packet is fragmented
    fragment_offset = ip_frag % 8192
    ip_data_length = ip_length - 4 * (ip_version_header_len % 16)

    if (fragment_offset > 0):
        # This is a secondary (not first) part of a fragmented packet, so ignore it
        #if (verbose_level >= 13):
        #    print "A fragmented packet which is not the first part, so skip it"
        #return (None, 0)
        return packet_info

    #if ( (protocol != 6) and (protocol != 17) ):
    #    # For non UDP/TCP packets, set source and destination ports to 0
    #    port_src = 0
    #    port_dst = 0
    #else:
    #    # Otherwise, extract source and destination ports
    #    (port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[20:24])

    if (protocol == 6):
        # This is a TCP packet
        (port_src, port_dst, tcp_seq_num_1, tcp_seq_num_2, tcp_ack_num_1, tcp_ack_num_2, tcp_data_offset_res_ns, tcp_flags) = struct.unpack('>HHHHHHBB' , ethernet_packet[20:34])
        tcp_sqn = (tcp_seq_num_1 << 16) + tcp_seq_num_2
        #tcp_header_length = 4 * tcp_data_offset_res_ns
        tcp_header_length = tcp_data_offset_res_ns >> 2
        #print "tcp_data_offset_res_ns =", tcp_data_offset_res_ns, "\ttcp_header_length =", tcp_header_length
    elif (protocol == 17):
        # This is a UDP packet
        # Extract source and destination ports
        #(port_src, port_dst) = struct.unpack('>HH' , ethernet_packet[20:24])
        (port_src, port_dst, udp_length) = struct.unpack('>HHH' , ethernet_packet[20:26])
        #tcp_flags = -1
        #tcp_sqn = -1
    else:
        # For non UDP/TCP packets, set source and destination ports to 0
        port_src = 0
        port_dst = 0
        #tcp_flags = -1
        #tcp_sqn = -1

    # Generate packet id
    packet_info.src_ip_1 = ip_src_1
    packet_info.src_ip_2 = ip_src_2
    packet_info.src_ip_3 = ip_src_3
    packet_info.src_ip_4 = ip_src_4
    packet_info.dst_ip_1 = ip_dst_1
    packet_info.dst_ip_2 = ip_dst_2
    packet_info.dst_ip_3 = ip_dst_3
    packet_info.dst_ip_4 = ip_dst_4
    packet_info.src_port = port_src
    packet_info.dst_port = port_dst
    packet_info.flow_id = str(ip_src_1) + "." + str(ip_src_2) + "." + \
                          str(ip_src_3) + "." + str(ip_src_4) + "_" + str(port_src) + "_" + \
                          str(ip_dst_1) + "." + str(ip_dst_2) + "." + \
                          str(ip_dst_3) + "." + str(ip_dst_4) + "_" + str(port_dst) + "_" + str(protocol)
    packet_info.ip_data_length = ip_data_length

    #print "flow_id =", packet_info.flow_id

    packet_info.protocol = protocol
    if (protocol == 6):
        # This is a TCP packet
        packet_info.tcp_flags = tcp_flags
        packet_info.tcp_sqn = tcp_sqn
        packet_info.tcp_header_length = tcp_header_length
        packet_info.l4_data_size = ip_data_length - tcp_header_length
        #print "ip_data_length =", ip_data_length, "    \ttcp_header_length =", tcp_header_length, "\tl4_data_size =", packet_info.l4_data_size
    elif (protocol == 17):
        # This is a UDP packet
        packet_info.udp_length = udp_length
        #packet_info.l4_data_size = udp_length - 8
        packet_info.l4_data_size = ip_data_length - 8
        #print "ip_data_length =", ip_data_length, "\tudp_length =", udp_length, "\tl4_data_size =", packet_info.l4_data_size

    packet_info.packet_length_ip = ip_length
    packet_info.packet_length_captured = len(ethernet_packet)

    #if (verbose_level >= 15):
    #    print "Packet id is " + packet_id

    return packet_info

def ProcessPCAPFile(pcap_file_name, all_configs):
    sys.stdout.write(time.strftime("%Y-%m-%d,%H:%M:%S") + " Processing pcap file " + pcap_file_name + "\n")
    # Open pcap file
    pcap_file_handler = open(pcap_file_name)
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    pcap_packet_counter = 0

    for timestamp, raw_packet in pcap_file:
        # Process this packet

        pcap_packet_counter += 1
        if ((pcap_packet_counter % all_configs[0].prone_all_flows_info_interval) == 0):
            for config in all_configs:
                RemoveExpiresRules(config, timestamp)
                ProneAllFlowsInfo(config, timestamp)
            sys.stdout.write(".")
            sys.stdout.flush()

        #packet_info = this.GeneratePacketID(raw_packet)
        #packet_info.timestamp = timestamp
        # The last packet id generator used for this packet
        LastGeneratePacketID = None

        for config in all_configs:
            # Check if we need to generate a new packet id
            if config.GeneratePacketID != LastGeneratePacketID:
                LastGeneratePacketID = config.GeneratePacketID
                try:
                    packet_info = LastGeneratePacketID(raw_packet)
                except:
                    # There was an error in packet id generation, so set packet info to a blank info to skip this packet
                    packet_info = PacketInfo()
                packet_info.timestamp = timestamp

                #print "Processing packet with flow_id: " + str(packet_info.flow_id)

            if packet_info.flow_id != None:
                # This is a packet that we want to process, so start processing it
                config.ProcessPacket(packet_info, config)
                #print "Processing packet with flow id " + str(packet_info.flow_id) + "_" + str(timestamp) + " for config " + str(config.config_id)

            # Check if we should show statistics
            if ((config.show_statistics_interval + config.last_time_shown_statistics) < timestamp):
                # We should show statistics
                config.ShowStatistics(config, timestamp)
                config.last_time_shown_statistics = timestamp

    sys.stdout.write("\n")
    sys.stdout.flush()

def ShowStatisticsNothing(config, timestamp):
    pass

def RemoveSingleRule(config, flow_id):
    # Remove a single rule with flow_id from the rule table

    # Remove rule from the flow table
    del config.installed_flows[flow_id]

    # Update flow info
    flow_info = config.all_flows_info[flow_id]
    flow_info.rule_removal_sampled_packet_count = flow_info.sampled_packet_count

def RemoveExpiresRules(config, timestamp):
    # Remove expired rules
    removed_count = 0
    for flow_id in config.installed_flows.keys():
        flow_installed_rule = config.installed_flows[flow_id]

        #expiry_time_idle = flow_installed_rule.last_packet_time + flow_installed_rule.timeout_idle
        #expiry_time_hard = flow_installed_rule.rule_install_time + flow_installed_rule.timeout_hard
        # Assume that timeouts are in milliseconds
        #expiry_time_idle = flow_installed_rule.last_packet_time  + (flow_installed_rule.timeout_idle * 0.001)
        #expiry_time_hard = flow_installed_rule.rule_install_time + (flow_installed_rule.timeout_hard * 0.001)
        #if (expiry_time_idle < expiry_time_hard):
        #    expiry_time = expiry_time_idle
        #else:
        #    expiry_time = expiry_time_hard

        #if ( (expiry_time + EPSILON) < timestamp):
        if CheckIfRuleExpired(flow_installed_rule, timestamp):
            # This rule is expired, so remove it
            # Record this in flow info
            config.all_flows_info[flow_id].rule_expiry_time = timestamp + RuleExpiredTime(flow_installed_rule, timestamp)
            #del config.installed_flows[flow_id]
            RemoveSingleRule(config, flow_id)
            removed_count += 1
            #print "Removing expired rule for flow with id " + str(flow_id) + " at time " + str(expiry_time)

    return removed_count

def ShowStatisticsRuleTableOccupancy(config, timestamp):

    # Remove expired rules
    removed_count = RemoveExpiresRules(config, timestamp)

    # Now print the number of rules in the table
    #config.log_file.write("# statistics:\tlen(installed_flows) = %8d\tremoved_count = %4d\n" % (len(config.installed_flows), removed_count))
    config.log_file.write("# statistics:\tlen(installed_flows) = %8d\n" % (len(config.installed_flows)))

def ProneAllFlowsInfo(config, timestamp):
    # Go through all flows records and remove those that are expired
    oldest_time_to_keep = timestamp - config.maximum_flow_idle_time

    for flow_id in config.all_flows_info.keys():
        flow_info = config.all_flows_info[flow_id]
        # Check to see if we should remove this flow
        #if flow_info.last_packet_time < oldest_time_to_keep:
        if ( (flow_info.last_packet_time < oldest_time_to_keep) \
             and (flow_id not in config.installed_flows) ):
            # This flow should be removed
            # Remove any active flow rule for this flow
            if flow_id in config.installed_flows:
                RemoveSingleRule(config, flow_id)

            # Now print its information
            PrintFlowInfo(flow_info, config)

            # And finallyremove it from the dictionary
            del config.all_flows_info[flow_info.flow_id]

def FlushAllRemainingFlowsInfo(config):
    # Go through all flows records and remove any remaining one
    for flow_id in config.all_flows_info.keys():
        flow_info = config.all_flows_info[flow_id]

        # Remove any active flow rule for this flow
        if flow_id in config.installed_flows:
            RemoveSingleRule(config, flow_id)

        # Now print its information
        PrintFlowInfo(flow_info, config)

        # And finally remove it from the dictionary
        del config.all_flows_info[flow_info.flow_id]

def PrintFlowInfo(flow_info, config):
    if config.verbose_level >= 6:

        #print "flow_info.flow_id =", flow_info.flow_id, "\tflow_info.protocol =", flow_info.protocol

        info_sampled_packet_info = ""
        if config.log_sampled_packet_size :
            for current_sampled_packet_size in flow_info.sampled_packet_sizes:
                info_sampled_packet_info += "\t" + str(current_sampled_packet_size)

        if config.log_sampled_packet_interarrival_time:
            for current_sampled_packet_interarrival_time in flow_info.sampled_packet_interarrival_times:
                info_sampled_packet_info += "\t" + str(current_sampled_packet_interarrival_time)

        if ((flow_info.protocol == 6) or (flow_info.protocol == 17)):
            # This is a TCP or UDP flow
            if config.log_sampled_packet_size :
                for current_sampled_packet_l4_size in flow_info.sampled_packet_l4_data_size:
                    info_sampled_packet_info += "\t" + str(current_sampled_packet_l4_size)

        if (flow_info.protocol == 6):
            # This is a TCP flow
            if config.log_sampled_packet_tcp_flag:
                for current_sampled_packet_tcp_flag in flow_info.sampled_packet_tcp_flags:
                    info_sampled_packet_info += "\t" + str(current_sampled_packet_tcp_flag)
            if config.log_sampled_packet_tcp_sqn:
                for current_sampled_packet_tcp_sqn in flow_info.sampled_packet_tcp_sqn:
                    info_sampled_packet_info += "\t" + str(current_sampled_packet_tcp_sqn)

        if (flow_info.rule_installed) and (flow_info.rule_info != None):
            timeout_idle = flow_info.rule_info.timeout_idle
        else:
            timeout_idle = -1
        config.log_file.write("%-47s\t%d\t%d\t%d" \
                "\t%d\t%d" \
                "\t%f\t%f" \
                "\t%f\t%f\t%f" \
                "\t%s\t%d\t%f\t%d" \
                "\t%f\t%d\t%d" \
                "\t%d\t%d" \
                "\t%d\t%d" \
                "\t%d" \
                "%s\n" \
                % (flow_info.flow_id, flow_info.protocol, flow_info.packet_count , flow_info.sampled_packet_count, \
                flow_info.flow_byte_sum, flow_info.sampled_flow_byte_sum, \
                flow_info.first_packet_time, flow_info.last_packet_time, \
                flow_info.packet_interarrival_max, flow_info.first_sampled_packet_time, flow_info.last_sampled_packet_time, \
                flow_info.rule_installed, flow_info.rule_installed_counter, flow_info.first_packet_time_rule, flow_info.packet_count_rule, \
                flow_info.rule_expiry_time, flow_info.sampling_k, flow_info.rule_command_count, \
                flow_info.packet_count_table_miss, flow_info.flow_byte_sum_table_miss, \
                flow_info.packet_count_table_miss_after_rule, flow_info.flow_byte_sum_table_miss_after_rule, \
                timeout_idle,
                info_sampled_packet_info))

def PrintFlowInfoHeader(config):
    if config.verbose_level >= 6:
        info_sampled_packet_info = ""
        if config.log_sampled_packet_size :
            info_sampled_packet_info += "\tsampled_packet_sizes"
        if config.log_sampled_packet_interarrival_time :
            info_sampled_packet_info += "\tsampled_packet_interarrival_time"
        if config.log_sampled_packet_size :
            info_sampled_packet_info += "\tsampled_packet_l4_data_sizes"
        if config.log_sampled_packet_tcp_flag:
            info_sampled_packet_info += "\tsampled_packet_tcp_flag"
        if config.log_sampled_packet_tcp_sqn:
            info_sampled_packet_info += "\tsampled_packet_tcp_sqn"

        config.log_file.write("#flow_id\tprotocol\tpacket_count\tsampled_packet_count"\
                "\tflow_byte_sum\tsampled_flow_byte_sum" \
                "\tfirst_packet_time\tlast_packet_time" \
                "\tpacket_interarrival_max\tfirst_sampled_packet_time\tlast_sampled_packet_time"\
                "\trule_installed\trule_installed_counter\tfirst_packet_time_rule\tpacket_count_rule" \
                "\trule_expiry_time\tsampling_k\trule_command_count" \
                "\tpacket_count_table_miss\tflow_byte_sum_table_miss" \
                "\tpacket_count_table_miss_after_rule\tflow_byte_sum_table_miss_after_rule" \
                "\ttimeout_idle" \
                + info_sampled_packet_info +  "\n")

def CheckWhetherToSample(sampling_config, packet_count):
    # Check whether we should sample current packet or not
    ## If we should sample, then the second returned boolen is True if it was selected deterministically

    # Start with checking with deterministic sampling
    if  ( ( (packet_count - sampling_config.sampling_delta) % sampling_config.sampling_k ) \
          < sampling_config.sampling_m ):
        # Sample this packet deterministically
        #return (True, True)
        return True
    # Check for stochastic sampling
    elif (sampling_config.sampling_rho > 0 ) and ( random.randint(1, sampling_config.sampling_rho) == 1):
        # Sample this packet stochastically
        #return (True, False)
        return True

    #return (False, False)
    return False

def CheckInstalledRuleTimeApplyToPacket(flow_installed_rule, timestamp):
    # Check whether an installed will be applied to the packet received at timestamp

    #expiry_time_idle = flow_installed_rule.last_packet_time + flow_installed_rule.timeout_idle
    #expiry_time_hard = flow_installed_rule.rule_install_time + flow_installed_rule.timeout_hard
    # Assume that timeouts are in milliseconds
    #expiry_time_idle = flow_installed_rule.last_packet_time  + (flow_installed_rule.timeout_idle * 0.001)
    #expiry_time_hard = flow_installed_rule.rule_install_time + (flow_installed_rule.timeout_hard * 0.001)
    #if (expiry_time_idle < expiry_time_hard):
    #    expiry_time = expiry_time_idle
    #else:
    #    expiry_time = expiry_time_hard

    #if ( (flow_installed_rule.rule_install_time <= (timestamp + EPSILON)) and \
    #     ( (flow_installed_rule.rule_install_time + flow_installed_rule.timeout_hard + EPSILON) >= timestamp) and \
    #     ( (flow_installed_rule.last_packet_time + flow_installed_rule.timeout_idle + EPSILON) >= timestamp)):
    if ( (flow_installed_rule.rule_install_time <= (timestamp + EPSILON)) and \
         ( not CheckIfRuleExpired(flow_installed_rule, timestamp)) ):
         #( (timestamp - expiry_time) < EPSILON)):
        return True
    else:
        # Remove the rule if it is expired
        #if ( (expiry_time + EPSILON) >= timestamp):
            # This is an expired rule, so delete it
        return False

def RuleExpiredTime(flow_rule, timestamp):
    # Return how many seconds ago this rule was expired
    #expiry_time_idle = (timestamp - flow_rule.last_packet_time) * 1000 - flow_rule.timeout_idle
    #expiry_time_hard = (timestamp - flow_rule.rule_install_time) * 1000 - flow_rule.timeout_hard
    expiry_time_idle = (timestamp - flow_rule.last_packet_time) * IDLE_TIMEOUT_CONSTANT_MULTIPLER - flow_rule.timeout_idle
    expiry_time_hard = (timestamp - flow_rule.rule_install_time) * IDLE_TIMEOUT_CONSTANT_MULTIPLER - flow_rule.timeout_hard
    if (expiry_time_idle > expiry_time_hard):
        expiry_time = expiry_time_idle
    else:
        expiry_time = expiry_time_hard

    return expiry_time

def CheckIfRuleExpired(flow_rule, timestamp):
    if ( RuleExpiredTime(flow_rule, timestamp) > EPSILON):
        # This flow is expired
        return True
    else:
        # This flow is not expired yet
        return False

def ProcessPacketLightHHDetection(packet_info, config):

    #print "Processing a packet of flow with id " + str(packet_info.flow_id) + " at time " + str(packet_info.timestamp)
    # Get flow information that this packet belongs to
    try:
        # If we already have an entry for this flow
        flow_info = config.all_flows_info[packet_info.flow_id]
    except KeyError:
        # This is the first packet of this flow, so create one for it
        flow_info = FlowInfo(config.installed_rule_sampling)
        config.all_flows_info[packet_info.flow_id] = flow_info

        flow_info.CopyPacketHeader(packet_info)
        flow_info.first_packet_time = packet_info.timestamp

    # Update flow information for this packet
    if (flow_info.last_packet_time > 0):
        # Check and update the maximum inter arrival time of packets
        packet_interarrival_time = packet_info.timestamp - flow_info.last_packet_time
        if (packet_interarrival_time > flow_info.packet_interarrival_max) :
            flow_info.packet_interarrival_max = packet_interarrival_time

    flow_info.last_packet_time = packet_info.timestamp
    flow_info.flow_byte_sum += packet_info.packet_length_ip
    flow_info.packet_count += 1

    if (packet_info.flow_id in config.installed_flows):
        # There is an active flow installed for this flow
        flow_installed_rule = config.installed_flows[packet_info.flow_id]

        # Check whether this rule was expired or not
        #expiry_time_idle = flow_installed_rule.last_packet_time + flow_installed_rule.timeout_idle
        #expiry_time_hard = flow_installed_rule.rule_install_time + flow_installed_rule.timeout_hard
        # Assume that timeouts are in milliseconds
        #expiry_time_idle = flow_installed_rule.last_packet_time  + (flow_installed_rule.timeout_idle * 0.001)
        #expiry_time_hard = flow_installed_rule.rule_install_time + (flow_installed_rule.timeout_hard * 0.001)
        #if (expiry_time_idle < expiry_time_hard):
        #    expiry_time = expiry_time_idle
        #else:
        #    expiry_time = expiry_time_hard

        #if ( (packet_info.timestamp - expiry_time) > EPSILON):
        if CheckIfRuleExpired(flow_installed_rule, packet_info.timestamp):
            # This rule is already expired, so remove it from table
            #del config.installed_flows[packet_info.flow_id]
            #print config.config_id + ": Removing expired rule " + str(packet_info.flow_id) + " at time "\
            #       + str(packet_info.timestamp) + "\t, packet_interarrival_time = " + str(IDLE_TIMEOUT_CONSTANT_MULTIPLER*packet_interarrival_time) \
            #       + ",\t idle_timeout = " + str(flow_installed_rule.timeout_idle)
            RemoveSingleRule(config, packet_info.flow_id)
            flow_installed_rule = None
            #print "Removing expired rule for flow with id " + str(packet_info.flow_id) + " at time "\
            #       + str(expiry_time) + " (" + str(expiry_time - packet_info.timestamp) + "," + str(expiry_time) + "," + str(EPSILON) + ")"

    else:
        flow_installed_rule = None

    # Check whether there is an active flow entry for this packet or not
    #if (flow_installed_rule != None) and (CheckInstalledRuleTimeApplyToPacket(flow_installed_rule, packet_info.timestamp)):
    if (flow_installed_rule != None) and (flow_installed_rule.rule_install_time <= (packet_info.timestamp + EPSILON)) :
        # There is an active flow installed for this flow
        flow_installed_rule.packet_count += 1
        flow_installed_rule.last_packet_time = packet_info.timestamp
        flow_info.packet_count_rule += 1

        if (CheckWhetherToSample(flow_installed_rule.sampling_config, flow_installed_rule.packet_count)):
            # This packet is selected for sampling, so process it
            config.ProcessSampledPacket(flow_info, packet_info, flow_installed_rule, config)

    else:
        # There is no active flow rule installed for this flow
        # It could also be a result of the new rule not being installed yet
        config.catchall_flow_installed_rule.packet_count += 1
        config.catchall_flow_installed_rule.last_packet_time = packet_info.timestamp
        config.catchall_flow.packet_count += 1
        config.catchall_flow.last_packet_time = packet_info.timestamp
        flow_info.packet_count_table_miss += 1
        flow_info.flow_byte_sum_table_miss += packet_info.packet_length_ip

        if (flow_info.rule_installed):
            # There was a rule installed for this flow in past
            flow_info.packet_count_table_miss_after_rule += 1
            flow_info.flow_byte_sum_table_miss_after_rule += packet_info.packet_length_ip
            #print "A new packet come while previously installed but expired rule for flow with id " + str(packet_info.flow_id)  + " at time " + str(packet_info.timestamp)
            #print "inter_arrival= " + str(IDLE_TIMEOUT_CONSTANT_MULTIPLER*packet_interarrival_time) + "\tflow_size= " + str(flow_info.packet_count) + "\tsample_count=  " + str(flow_info.sampled_packet_count) + "\tidle_timeout= " + str(flow_info.rule_info.timeout_idle) + "\texpiry= " + str(IDLE_TIMEOUT_CONSTANT_MULTIPLER*packet_interarrival_time - flow_info.rule_info.timeout_idle) + "\tflow=" + str(packet_info.flow_id)

        if (CheckWhetherToSample(config.catchall_flow_installed_rule.sampling_config, config.catchall_flow_installed_rule.packet_count)):
            # This packet is selected for sampling, so process it
            config.ProcessSampledPacket(flow_info, packet_info, None, config)

            config.catchall_flow.last_sampled_packet_time = packet_info.timestamp
            config.catchall_flow.sampled_flow_byte_sum += packet_info.packet_length_ip
            config.catchall_flow.sampled_packet_count += 1

            #print "flow_id = " + str(packet_info.flow_id) \
            #      + " flow_installed_rule is None = " + str(flow_installed_rule == None) \
            #      + " flow_info.sampled_packet_count = " + str(flow_info.sampled_packet_count) \
            #      + " flow_info.rule_removal_sampled_packet_count = " + str(flow_info.rule_removal_sampled_packet_count)
            # Check to see if we should install a new rule
            #if (flow_installed_rule == None):
            if ((flow_installed_rule == None) and \
                ( (flow_info.sampled_packet_count - flow_info.rule_removal_sampled_packet_count) \
                   >= config.install_rule_sample_threshold )):
                #print "Installing a new rule for flow_id = " + str(packet_info.flow_id) \
                # We should also install a rule for this flow
                if not flow_info.rule_installed :
                    # This is the first time that we install a rule for this flow
                    flow_info.rule_info = RuleInfo(config.installed_rule_sampling)
                    flow_installed_rule = flow_info.rule_info
                    #flow_installed_rule.timeout_hard = config.rule_timeout_hard
                    #flow_installed_rule.timeout_idle = config.rule_timeout_idle
                    # Set the initial idle timeout
                    #config.SetInitialIdleTimeout(flow_info, packet_info, flow_installed_rule, config)
                    flow_installed_rule.rule_install_time = packet_info.timestamp + config.rule_install_delay_first
                else:
                    # This is a rule reinstallation, so start with the previously expired rule
                    flow_installed_rule = flow_info.rule_info
                    # The previous rule expired before the flow, so only increase the idle and hard timeouts without changing the sampling k
                    #flow_installed_rule.timeout_idle = math.ceil(flow_installed_rule.timeout_idle * config.rule_timeout_idle_beta)
                    #flow_installed_rule.timeout_hard = math.ceil(flow_installed_rule.timeout_hard * config.rule_timeout_hard_gamma)
                    #flow_installed_rule.timeout_hard = config.rule_timeout_hard
                    #flow_installed_rule.timeout_idle = config.rule_timeout_idle
                    # Do not change any timeout, use previous expired rule values
                    #flow_installed_rule.sampling_config.sampling_k = math.ceil(flow_installed_rule.sampling_config.sampling_k / config.installed_rule_sampling.sampling_alpha)
                    # Incrase idle timeout until we receive another sampled packet
                    # Disabled for now, conflicting with idle timeout calcualtion from flow size
                    #flow_installed_rule.timeout_idle = math.ceil(flow_installed_rule.timeout_idle * config.rule_timeout_idle_zeta)
                    # Now update idle timeout for this packet
                    #config.UpdateIdleTimeout(flow_info, packet_info, flow_installed_rule, config)
                    flow_installed_rule.rule_install_time = packet_info.timestamp + config.rule_install_delay

                # Set the initial idle timeout
                config.SetInitialIdleTimeout(flow_info, packet_info, flow_installed_rule, config)
                #config.installed_flows[packet_info.flow_id] = flow_installed_rule
                InstallFlowRule(config, packet_info.flow_id, flow_installed_rule, packet_info.timestamp)
                #flow_info.packet_count_rule = 0

                flow_info.rule_command_count += 1
                flow_info.rule_installed = True
                flow_info.rule_installed_counter += 1
                #print "Adding a rule for flow with id " + str(packet_info.flow_id)  + " at time " + str(packet_info.timestamp)

def EvictRuleLRU(config, timestamp):
    # Evict a rule based on Least Recently Used policy
    flow_to_evict_id = None
    flow_to_evict_last_packet_time = INFINITE_TIME
    flow_to_evict_packet_count = INFINITE_TIME
    flow_to_evict_rule_install_time = INFINITE_TIME

    for flow_id, flow_installed_rule in config.installed_flows.iteritems():
        #print "Checking rule " + str(flow_id) + \
        #      " where last_packet_time = " + str(flow_installed_rule.last_packet_time) + \
        #      " and packet_count = " + str(flow_installed_rule.packet_count) + \
        #      " and rule_install_time = " + str(flow_installed_rule.rule_install_time)
        if CheckIfRuleExpired(flow_installed_rule, timestamp):
            # This rule is already expired, so evict it
            #print "Find an expired rule: " + str(flow_id)
            flow_to_evict_id = flow_id
            break

        if ((flow_installed_rule.packet_count == 0) and (flow_to_evict_packet_count > 0)) or \
           ((flow_installed_rule.last_packet_time < flow_to_evict_last_packet_time) and
            ((flow_installed_rule.packet_count == 0) or (flow_to_evict_packet_count > 0))) or \
           ((flow_installed_rule.last_packet_time == flow_to_evict_last_packet_time) and \
            (flow_installed_rule.packet_count < flow_to_evict_packet_count)) or \
           ((flow_installed_rule.last_packet_time == flow_to_evict_last_packet_time) and \
            (flow_installed_rule.packet_count == flow_to_evict_packet_count) and \
            (flow_installed_rule.rule_install_time < flow_to_evict_rule_install_time)):
            # This is a better rule to evict
            flow_to_evict_id = flow_id
            flow_to_evict_packet_count = flow_installed_rule.packet_count
            flow_to_evict_last_packet_time = flow_installed_rule.last_packet_time
            flow_to_evict_rule_install_time = flow_installed_rule.rule_install_time

    # Evict the best rule that we found
    #print "Evicting (based on LRU) rule " + str(flow_to_evict_id) + " at " + str(timestamp)
    RemoveSingleRule(config, flow_to_evict_id)

def EvictRuleLFU(config, timestamp):
    # Evict a rule based on Least Frequently Used policy
    flow_to_evict_id = None
    flow_to_evict_packet_count = INFINITE_TIME
    flow_to_evict_last_packet_time = INFINITE_TIME

    for flow_id, flow_installed_rule in config.installed_flows.iteritems():
        #print "Checking rule " + str(flow_id) + \
        #      " where last_packet_time = " + str(flow_installed_rule.last_packet_time) + \
        #      " and packet_count = " + str(flow_installed_rule.packet_count) + \
        #      " and rule_install_time = " + str(flow_installed_rule.rule_install_time)
        if CheckIfRuleExpired(flow_installed_rule, timestamp):
            # This rule is already expired, so evict it
            #print "Find an expired rule: " + str(flow_id)
            flow_to_evict_id = flow_id
            break

        if (flow_installed_rule.packet_count < flow_to_evict_packet_count) or \
           ((flow_installed_rule.packet_count == flow_to_evict_packet_count) and \
            (flow_installed_rule.rule_install_time < flow_to_evict_rule_install_time)) or \
           ((flow_installed_rule.packet_count == flow_to_evict_packet_count) and \
            (flow_installed_rule.rule_install_time == flow_to_evict_rule_install_time) and \
            (flow_installed_rule.last_packet_time < flow_to_evict_last_packet_time)):
            # This is a better rule to evict
            flow_to_evict_id = flow_id
            flow_to_evict_packet_count = flow_installed_rule.packet_count
            flow_to_evict_last_packet_time = flow_installed_rule.last_packet_time
            flow_to_evict_rule_install_time = flow_installed_rule.rule_install_time

    # Evict the best rule that we found
    #print "Evicting (based on LFU) rule " + str(flow_to_evict_id) + " at " + str(timestamp)
    #print "Evicting rule " + str(flow_to_evict_id)
    RemoveSingleRule(config, flow_to_evict_id)

def EvictRuleLongestEstimatedNextPacketArrival(config, timestamp):
    # Evict a rule based on the estimated wait time for the next arrival packet
    flow_to_evict_id = None
    flow_to_evict_estimated_next_packet_arrival = -1 * INFINITE_TIME

    #print "-------------------------------------------------"
    for flow_id, flow_installed_rule in config.installed_flows.iteritems():
        if CheckIfRuleExpired(flow_installed_rule, timestamp):
            # This rule is already expired, so evict it
            #print "Find an expired rule: " + str(flow_id)
            flow_to_evict_id = flow_id
            break

        # Estimate the arrival time of next packet for this flow
        estimated_next_packet_arrival = (timestamp - flow_installed_rule.last_packet_time) * IDLE_TIMEOUT_CONSTANT_MULTIPLER + \
                (flow_installed_rule.timeout_idle / config.rule_timeout_idle_zeta)
        #print "Checking rule " + str(flow_id) + \
        #      " : last_packet_time = " + str(flow_installed_rule.last_packet_time) + \
        #      ", packet_count = " + str(flow_installed_rule.packet_count) + \
        #      ", rule_install_time = " + str(flow_installed_rule.rule_install_time) + \
        #      ", estimated_next_packet_arrival = " + str(estimated_next_packet_arrival)

        if (estimated_next_packet_arrival > flow_to_evict_estimated_next_packet_arrival):
            # This is a better rule to evict
            flow_to_evict_id = flow_id
            flow_to_evict_estimated_next_packet_arrival = estimated_next_packet_arrival

    # Evict the best rule that we found
    #print "Evicting (based on ENPA) rule " + str(flow_to_evict_id) + " at " + str(timestamp)
    RemoveSingleRule(config, flow_to_evict_id)

def InstallFlowRule(config, flow_id, flow_rule, timestamp):
    # Install a rule in the flow table
    #print "Installing frule for flow " + str(flow_id) + " at time " + str(timestamp)

    # First, check whether the table is full
    if (len(config.installed_flows) >= config.flow_table_maximum_size):
        # The flow table is full, so evict a rule
        #print "Table is full (size = " + str(len(config.installed_flows)) + "), so evict a rule"
        config.EvictRule(config, timestamp)

    # Now install new rule
    config.installed_flows[flow_id] = flow_rule
    #flow_rule.previous_sampled_packet_time = flow_rule.rule_install_time
    flow_rule.previous_sampled_sampling_k = 0
    flow_rule.last_packet_time = flow_rule.rule_install_time
    flow_rule.packet_count = 0
    flow_rule.sampled_packet_order_number = 1

def ProcessSampledPacketLightHHDetection(flow_info, packet_info, flow_installed_rule, config):
    # Check if this is the first sampled packet for this flow
    #if not flow_info.first_sampled_packet_time:
    #    flow_info.first_sampled_packet_time = packet_info.timestamp

    # Record the size of this packet if we want to print it later on
    if config.log_sampled_packet_size:
        flow_info.sampled_packet_sizes.append(packet_info.packet_length_ip)
        if ((packet_info.protocol == 6) or (packet_info.protocol == 17)):
            # If this is a TCP or UDP packet
            flow_info.sampled_packet_l4_data_size.append(packet_info.l4_data_size)

    # Update flow information for this sampled packet
    flow_info.last_sampled_packet_time = packet_info.timestamp
    flow_info.sampled_flow_byte_sum += packet_info.packet_length_ip
    flow_info.sampled_packet_count += 1
    if (flow_info.sampled_packet_count == 1):
        # This is the first sampled packet form this flow, so record its time
        flow_info.first_sampled_packet_time = packet_info.timestamp

    # Now update sampling parameters and rule timeouts, if it is sampled by the rule
    if flow_installed_rule != None:
        flow_installed_rule.sampling_config.sampling_k = math.ceil(flow_installed_rule.sampling_config.sampling_k * config.installed_rule_sampling.sampling_alpha)
        flow_installed_rule.timeout_idle = math.ceil(flow_installed_rule.timeout_idle * config.rule_timeout_idle_beta)
        flow_installed_rule.timeout_hard = math.ceil(flow_installed_rule.timeout_hard * config.rule_timeout_hard_gamma)
        flow_info.rule_command_count += 1

def ProcessSampledPacketRecordOnly(flow_info, packet_info, flow_installed_rule, config):
    # Check if this is the first sampled packet for this flow

    #print "flow_info.protocol =", flow_info.protocol, "\tpacket_info.protocol =", packet_info.protocol

    # Record the size and interarrival time of this packet if we want to print it later on
    if config.log_sampled_packet_size:
        flow_info.sampled_packet_sizes.append(packet_info.packet_length_ip)

    if (flow_info.sampled_packet_count == 0):
        flow_info.last_sampled_packet_interarrival_time = -1
    else:
        flow_info.last_sampled_packet_interarrival_time = packet_info.timestamp - flow_info.last_sampled_packet_time

    if config.log_sampled_packet_interarrival_time:
        flow_info.sampled_packet_interarrival_times.append(flow_info.last_sampled_packet_interarrival_time)
        #if (flow_info.sampled_packet_count == 0):
        #    flow_info.sampled_packet_interarrival_times.append(-1)
        #else:
        #    flow_info.sampled_packet_interarrival_times.append(packet_info.timestamp - flow_info.last_sampled_packet_time)

    if (packet_info.protocol == 6):
        # This is a TCP packet
        if config.log_sampled_packet_tcp_flag:
            flow_info.sampled_packet_tcp_flags.append(packet_info.tcp_flags)

        if config.log_sampled_packet_tcp_sqn:
            flow_info.sampled_packet_tcp_sqn.append(packet_info.tcp_sqn)

        if config.log_sampled_packet_size:
            flow_info.sampled_packet_l4_data_size.append(packet_info.l4_data_size)
    elif (packet_info.protocol == 17):
        # This is a UDP packet
        if config.log_sampled_packet_size:
            flow_info.sampled_packet_l4_data_size.append(packet_info.l4_data_size)

    # Update flow information for this sampled packet
    flow_info.last_sampled_packet_time = packet_info.timestamp
    flow_info.sampled_flow_byte_sum += packet_info.packet_length_ip
    flow_info.sampled_packet_count += 1

    if (flow_info.sampled_packet_count == 1):
        # This is the first sampled packet form this flow, so record its time
        flow_info.first_sampled_packet_time = packet_info.timestamp

def SetNewIdleTimeout(flow_installed_rule, config, new_idle_timeout):

    # Check whether we want to only increase the idle time out or not
    if (config.idle_timeout_increasing_only):
        # We should only use the new value if it is higher than old idle timeout, or it has the default infinite value
        if ( (new_idle_timeout > flow_installed_rule.timeout_idle) or (flow_installed_rule.timeout_idle == INFINITE_TIME)):
            flow_installed_rule.timeout_idle = new_idle_timeout
    else:
        flow_installed_rule.timeout_idle = new_idle_timeout
    # Check that it is in the range of minimum and maximum idle timeouts
    flow_installed_rule.timeout_idle = max(flow_installed_rule.timeout_idle, config.rule_timeout_idle_min)
    flow_installed_rule.timeout_idle = min(flow_installed_rule.timeout_idle, config.rule_timeout_idle_max)

def SetInitialIdleTimeoutConstant(flow_info, packet_info, flow_installed_rule, config):
    # Set the initial timeouts to constant values
    flow_installed_rule.timeout_hard = config.rule_timeout_hard
    flow_installed_rule.timeout_idle = config.rule_timeout_idle

def SetInitialIdleTimeoutBasedOnPacketInterArrivalTimes(flow_info, packet_info, flow_installed_rule, config):
    # Set the initial timeouts based on sampled packet inter-arrival times

    if (flow_info.sampled_packet_count < 2):
        # We only received one sampled packet for this flow, so there is nothing we can do for it
        # Use constant idle timeout instead
        SetInitialIdleTimeoutConstant(flow_info, packet_info, flow_installed_rule, config)
        return

    # While there was no rule installed for this rule (either because it was expired or no rule installed at all), everything was sampled by catchall rule
    #number_of_packets_between_samples = config.catchall_flow_installed_rule.sampling_config.sampling_k
    number_of_packets_between_samples = config.catchall_flow_installed_rule.sampling_config.sampling_rho

    if flow_info.rule_installed:
        # There was a rule installed in past, so some packets were also processed by that rule before it expires
        # We can assume that k/2 packets were matched.
        number_of_packets_between_samples += flow_info.rule_info.sampling_config.sampling_k // 2
        #print "kset_initial_idle_timeout estimated_packet_count= " + str(number_of_packets_between_samples) + "\tprevious_k= " + str(flow_info.rule_info.sampling_config.sampling_k) + "\tflow=" + str(packet_info.flow_id)

    average_inter_packet_arrival_time = flow_info.last_sampled_packet_interarrival_time / number_of_packets_between_samples

    # Set idle timeout as a multiplier of average inter packet arrival time
    # The multiplier is zeta to the power of sampled packet counter
    try:
        new_idle_timeout = math.ceil(average_inter_packet_arrival_time * IDLE_TIMEOUT_CONSTANT_MULTIPLER \
                                                     * (config.rule_timeout_idle_zeta ** flow_info.sampled_packet_count))
    except:
        pass

    SetNewIdleTimeout(flow_installed_rule, config, new_idle_timeout)

    #print "set_initial_idle_timeout average_inter_packet_arrival_time= " + str(IDLE_TIMEOUT_CONSTANT_MULTIPLER*average_inter_packet_arrival_time) + "\tidle_timeout= " + str(flow_info.rule_info.timeout_idle) + "\tflow_size= " + str(flow_info.packet_count) + "\testimated_packet_count= " + str(number_of_packets_between_samples) + "\tflow=" + str(packet_info.flow_id)

def UpdateIdleTimeoutUnchanged(flow_info, packet_info, flow_installed_rule, config):
    # Do not change idle timeout
    pass

def UpdateIdleTimeoutBasedOnFlowSize(flow_info, packet_info, flow_installed_rule, config):
    # Now update sampling parameters and rule timeouts, if it is sampled by the rule
    if flow_installed_rule != None:
        # Set idle timeout as a multiplier of fixed idle timeout
        # The multiplier is zeta to the power of sampled packet counter
        try:
            flow_installed_rule.timeout_idle = math.ceil(config.rule_timeout_idle * (config.rule_timeout_idle_zeta ** flow_info.sampled_packet_count))
        except:
            pass

        # Check that it is in the range of minimum and maximum idle timeouts
        flow_installed_rule.timeout_idle = max(flow_installed_rule.timeout_idle, config.rule_timeout_idle_min)
        flow_installed_rule.timeout_idle = min(flow_installed_rule.timeout_idle, config.rule_timeout_idle_max)

        # Now update sampling parameters and rule timeouts, if it is sampled by the rule
        flow_installed_rule.sampling_config.sampling_k = math.ceil(flow_installed_rule.sampling_config.sampling_k * config.installed_rule_sampling.sampling_alpha)
        #flow_installed_rule.timeout_hard = math.ceil(flow_installed_rule.timeout_hard * config.rule_timeout_hard_gamma)
        flow_info.rule_command_count += 1

def UpdateIdleTimeoutBasedOnFlowSizeAndPacketInterArrivalTimes(flow_info, packet_info, flow_installed_rule, config):
    # Now update sampling parameters and rule timeouts, if it is sampled by the rule
    if flow_installed_rule != None:
        # If received another sampled packet, so estimate the inter packet arrival time
        #average_inter_packet_arrival_time = (flow_info.last_sampled_packet_time - flow_installed_rule.rule_install_time) / flow_installed_rule.sampling_config.sampling_k
        if (flow_installed_rule.sampling_config.sampling_k > flow_installed_rule.previous_sampled_sampling_k):
            #average_inter_packet_arrival_time = (flow_info.last_sampled_packet_time - flow_installed_rule.previous_sampled_packet_time) \
            #                                    / (flow_installed_rule.sampling_config.sampling_k - flow_installed_rule.previous_sampled_sampling_k)
            average_inter_packet_arrival_time = flow_info.last_sampled_packet_interarrival_time \
                                                / (flow_installed_rule.sampling_config.sampling_k - flow_installed_rule.previous_sampled_sampling_k)
        else:
            #average_inter_packet_arrival_time = (flow_info.last_sampled_packet_time - flow_installed_rule.previous_sampled_packet_time) \
            #                                    / (flow_installed_rule.sampling_config.sampling_k)
            average_inter_packet_arrival_time = flow_info.last_sampled_packet_interarrival_time / flow_installed_rule.sampling_config.sampling_k

        #print "flow=" + str(packet_info.flow_id) + "\taverage_inter_packet= " + str(average_inter_packet_arrival_time) + "\tlast_inter_packet= " + str(flow_info.last_sampled_packet_interarrival_time);
        # Set idle timeout as a multiplier of average inter packet arrival time
        # The multiplier is zeta to the power of sampled packet counter
        try:
            #flow_installed_rule.timeout_idle = math.ceil(average_inter_packet_arrival_time * (config.rule_timeout_idle_zeta ** flow_info.sampled_packet_count))
            new_idle_timeout = math.ceil(average_inter_packet_arrival_time * IDLE_TIMEOUT_CONSTANT_MULTIPLER * \
                                         (config.rule_timeout_idle_zeta ** flow_info.sampled_packet_count))
        except:
            pass

        #print "update_idle_timeout new_idle_timeout= " + str(new_idle_timeout) + "\tcurrent_idle_timeout= " + str(flow_installed_rule.timeout_idle) + "\tflow= " + str(packet_info.flow_id)

        # Check that it is in the range of minimum and maximum idle timeouts
        #flow_installed_rule.timeout_idle = max(flow_installed_rule.timeout_idle, config.rule_timeout_idle_min)
        #flow_installed_rule.timeout_idle = min(flow_installed_rule.timeout_idle, config.rule_timeout_idle_max)
        SetNewIdleTimeout(flow_installed_rule, config, new_idle_timeout)

        # Now update sampling parameters and rule timeouts, if it is sampled by the rule
        #flow_installed_rule.previous_sampled_packet_time = flow_info.last_sampled_packet_time
        flow_installed_rule.previous_sampled_sampling_k = flow_installed_rule.sampling_config.sampling_k
        flow_installed_rule.sampling_config.sampling_k = math.ceil(flow_installed_rule.sampling_config.sampling_k * config.installed_rule_sampling.sampling_alpha)
        #flow_installed_rule.timeout_hard = math.ceil(flow_installed_rule.timeout_hard * config.rule_timeout_hard_gamma)
        flow_info.rule_command_count += 1

def ProcessSampledPacketIdleTimeoutBasedOnFlowSize(flow_info, packet_info, flow_installed_rule, config):

    ProcessSampledPacketRecordOnly(flow_info, packet_info, flow_installed_rule, config)
    config.UpdateIdleTimeout(flow_info, packet_info, flow_installed_rule, config)

def ProcessSampledPacketEstimateIdleTimeout(flow_info, packet_info, flow_installed_rule, config):

    ProcessSampledPacketRecordOnly(flow_info, packet_info, flow_installed_rule, config)

    # Now update sampling parameters and rule timeouts, if it is sampled by the rule
    if flow_installed_rule != None:
        # If received another sampled packet, so estimate the inter packet arrival time
        #average_inter_packet_arrival_time = (flow_info.last_sampled_packet_time - flow_installed_rule.rule_install_time) / flow_installed_rule.sampling_config.sampling_k
        if (flow_installed_rule.sampling_config.sampling_k > flow_installed_rule.previous_sampled_sampling_k):
            #average_inter_packet_arrival_time = (flow_info.last_sampled_packet_time - flow_installed_rule.previous_sampled_packet_time) \
            #                                    / (flow_installed_rule.sampling_config.sampling_k - flow_installed_rule.previous_sampled_sampling_k)
            average_inter_packet_arrival_time = flow_info.last_sampled_packet_interarrival_time \
                                                / (flow_installed_rule.sampling_config.sampling_k - flow_installed_rule.previous_sampled_sampling_k)
        else:
            #average_inter_packet_arrival_time = (flow_info.last_sampled_packet_time - flow_installed_rule.previous_sampled_packet_time) \
            #                                    / (flow_installed_rule.sampling_config.sampling_k)
            average_inter_packet_arrival_time = flow_info.last_sampled_packet_interarrival_time / flow_installed_rule.sampling_config.sampling_k

        # And calculate idle timeout based on average inter packet arrival time
        #flow_installed_rule.timeout_idle = math.ceil(average_inter_packet_arrival_time * config.rule_timeout_idle_zeta)
        flow_installed_rule.timeout_idle = math.ceil( config.rule_timeout_idle_theta * average_inter_packet_arrival_time * config.rule_timeout_idle_zeta \
                                                      + (1 - config.rule_timeout_idle_theta) * flow_installed_rule.timeout_idle)
        # Check that it is in the range of minimum and maximum idle timeouts
        flow_installed_rule.timeout_idle = max(flow_installed_rule.timeout_idle, config.rule_timeout_idle_min)
        flow_installed_rule.timeout_idle = min(flow_installed_rule.timeout_idle, config.rule_timeout_idle_max)

        flow_installed_rule.previous_sampled_sampling_k = flow_installed_rule.sampling_config.sampling_k
        flow_installed_rule.sampling_config.sampling_k = math.ceil(flow_installed_rule.sampling_config.sampling_k * config.installed_rule_sampling.sampling_alpha)
        #flow_installed_rule.previous_sampled_packet_time = flow_info.last_sampled_packet_time
        #flow_installed_rule.timeout_idle = math.ceil(flow_installed_rule.timeout_idle * config.rule_timeout_idle_beta)
        #flow_installed_rule.timeout_hard = math.ceil(flow_installed_rule.timeout_hard * config.rule_timeout_hard_gamma)
        flow_info.rule_command_count += 1

def ProcessSampledPacketEstimateIdleTimeoutConsecutivePackets(flow_info, packet_info, flow_installed_rule, config):

    ProcessSampledPacketRecordOnly(flow_info, packet_info, flow_installed_rule, config)

    # Now update sampling parameters and rule timeouts, if it is sampled by the rule
    if flow_installed_rule != None:
        # If received another consecutive sampled packet, update the estimated inter packet arrival time

        flow_installed_rule.sampled_packet_order_number += 1

        if (flow_installed_rule.sampled_packet_order_number > 1):
            # We had received the previous packet of this flow through sampling, so we can calcualte its inter packet arrival time
            #current_inter_packet_arrival_time = packet_info.timestamp - flow_installed_rule.previous_sampled_packet_time

            # And calculate idle timeout based on current inter packet arrival time
            #flow_installed_rule.timeout_idle = math.ceil( config.rule_timeout_idle_theta * current_inter_packet_arrival_time * config.rule_timeout_idle_zeta \
            #                                              + (1 - config.rule_timeout_idle_theta) * flow_installed_rule.timeout_idle)
            flow_installed_rule.timeout_idle = math.ceil( config.rule_timeout_idle_theta * flow_info.last_sampled_packet_interarrival_time * config.rule_timeout_idle_zeta \
                                                          + (1 - config.rule_timeout_idle_theta) * flow_installed_rule.timeout_idle)

            # Check that it is in the range of minimum and maximum idle timeouts
            flow_installed_rule.timeout_idle = max(flow_installed_rule.timeout_idle, config.rule_timeout_idle_min)
            flow_installed_rule.timeout_idle = min(flow_installed_rule.timeout_idle, config.rule_timeout_idle_max)

            #print "The idle timeout of flow " + flow_info.flow_id + " updated to " + str(flow_installed_rule.timeout_idle)
            #print "Idle timeout min is " + str(config.rule_timeout_idle_min) + " and max is " + str(config.rule_timeout_idle_max)

        if (flow_installed_rule.sampled_packet_order_number >= flow_installed_rule.sampling_config.sampling_m):
            # We already recived m consecutive sampled packet, so update sampling_k
            flow_installed_rule.sampled_packet_order_number = 0
            flow_installed_rule.previous_sampled_sampling_k = flow_installed_rule.sampling_config.sampling_k
            flow_installed_rule.sampling_config.sampling_k = math.ceil(flow_installed_rule.sampling_config.sampling_k * config.installed_rule_sampling.sampling_alpha)

        flow_info.rule_command_count += 1
        #flow_installed_rule.previous_sampled_packet_time = flow_info.last_sampled_packet_time

def ProcessPacketDynamicHHDetection(packet_info, config):

    #global catchall_flow

    # Get flow information that this packet belongs to
    try:
        # If we already have an entry for this flow
        flow_info = config.all_flows_info[packet_info.flow_id]
    except KeyError:
        # This is the first packet of this flow, so create one for it
        flow_info = FlowInfo(config.installed_rule_sampling)
        config.all_flows_info[packet_info.flow_id] = flow_info

        flow_info.CopyPacketHeader(packet_info)
        flow_info.first_packet_time = packet_info.timestamp

    # Update flow information for this packet
    flow_info.last_packet_time = packet_info.timestamp
    flow_info.flow_byte_sum += packet_info.packet_length_ip
    flow_info.packet_count += 1

    # Check to see if we should sample this packet
    # First, check to see if a rule is installed for this flow, or should use the catchall flow
    if flow_info.rule_installed:
        # There is a rule installed for this flow, so use sampling information for this specific flow
        flow_info.packet_count_rule += 1
        # Start with checking with deterministic sampling
        if  ( ( (flow_info.packet_count_rule - flow_info.sampling_delta) % flow_info.sampling_k ) \
              < flow_info.sampling_m ):
            # Sample this packet deterministically
            config.ProcessSampledPacket(flow_info, packet_info, True, config)
        # Check for stochastic sampling
        elif (flow_info.sampling_rho > 0 ) and ( random.randint(1, flow_info.sampling_rho) == 1):
            # Sample this packet deterministically
            config.ProcessSampledPacket(flow_info, packet_info, True, config)
    else:
        # Use catchall rule
        config.catchall_flow.packet_count_rule += 1
        config.catchall_flow.last_packet_time = packet_info.timestamp
        config.catchall_flow.flow_byte_sum += packet_info.packet_length_ip
        config.catchall_flow.packet_count += 1
        sample_this_packet = False
        sample_packet_deterministically = False

        # Start with checking with deterministic sampling
        if  ( ( (config.catchall_flow.packet_count_rule - config.catchall_flow.sampling_delta) \
                 % config.catchall_flow.sampling_k ) \
              < config.catchall_flow.sampling_m ):
            # Sample this packet deterministically
            sample_this_packet = True
            sample_packet_deterministically = True

        # Check for stochastic sampling
        elif (config.catchall_flow.sampling_rho > 0 ) and ( random.randint(1, config.catchall_flow.sampling_rho) == 1):
            # Sample this packet deterministically
            sample_this_packet = True
            sample_packet_deterministically = False

        if sample_this_packet:
            config.catchall_flow.last_sampled_packet_time = packet_info.timestamp
            config.catchall_flow.sampled_flow_byte_sum += packet_info.packet_length_ip
            config.catchall_flow.sampled_packet_count += 1
            # Check to see if we should install a rule
            if ( (flow_info.sampled_packet_count + 1) >= config.install_rule_sample_threshold ):
                # Now enable rule installed
                flow_info.rule_installed = True
                flow_info.rule_command_count = 1
                flow_info.first_packet_time_rule = packet_info.timestamp
                #flow_info.first_sampled_packet_time = packet_info.timestamp

            config.ProcessSampledPacket(flow_info, packet_info, None, config)

def ProcessSampledPacketDynamicHHDetection(flow_info, packet_info, flow_installed_rule, config):

    ProcessSampledPacketRecordOnly(flow_info, packet_info, flow_installed_rule, config)

    # Now update sampling parameters, if it is sampled by the rule
    if flow_installed_rule != None:
        flow_info.sampling_k = math.ceil(flow_info.sampling_k * config.installed_rule_sampling.sampling_alpha)
        flow_info.rule_command_count += 1

def FinalizeConfig(config):
    # This function finalizes a config object
    # Check to see if there is a defined ID, otherwise do nothing
    if not config.log_file_id:
        return

    config.all_flows_info = {}
    # Open log file
    config.log_file_name = config.log_directory + "/" + config.log_file_prefix + config.log_file_id + config.log_file_extension
    print "Openning log file " + config.log_file_name
    config.log_file = open(config.log_file_name, "w")
    PrintFlowInfoHeader(config)
    # Print config in the file
    config.log_file.write("#installed_rule_sampling.sampling_rho=%d\tinstalled_rule_sampling.sampling_delta=%d\t" \
            "installed_rule_sampling.sampling_m=%d\tinstalled_rule_sampling.sampling_k=%d\t" \
            "installed_rule_sampling.sampling_alpha=%f\tcatchall_sampling.sampling_rho=%d\t" \
            "catchall_sampling.sampling_delta=%d\tcatchall_sampling.sampling_m=%d\t" \
            "catchall_sampling.sampling_k=%d\tinstall_rule_sample_threshold=%d\t" \
            "maximum_flow_idle_time=%d\tverbose_level=%d\t" \
            "prone_all_flows_info_interval=%d\tend_of_world_timestamp=%d\t" \
            "log_file_name=%s\t" \
            "log_sampled_packet_size=%s\t" \
            "log_sampled_packet_interarrival_time=%s\t" \
            "log_sampled_packet_tcp_flag=%s\t" \
            "log_sampled_packet_tcp_sqn=%s\n"
            % (config.installed_rule_sampling.sampling_rho, config.installed_rule_sampling.sampling_delta,\
               config.installed_rule_sampling.sampling_m, config.installed_rule_sampling.sampling_k,\
               config.installed_rule_sampling.sampling_alpha, config.catchall_sampling.sampling_rho,\
               config.catchall_sampling.sampling_delta, config.catchall_sampling.sampling_m,\
               config.catchall_sampling.sampling_k, config.install_rule_sample_threshold,\
               config.maximum_flow_idle_time, config.verbose_level,\
               config.prone_all_flows_info_interval, config.end_of_world_timestamp,\
               config.log_file_name, 
               str(config.log_sampled_packet_size),
               str(config.log_sampled_packet_interarrival_time),
               str(config.log_sampled_packet_tcp_flag),
               str(config.log_sampled_packet_tcp_sqn)))

    # Create the flow entry representing packets matches the catchall rule
    config.catchall_flow = FlowInfo(config.catchall_sampling)
    config.catchall_flow.flow_id = '*'
    config.catchall_flow.protocol = -1

    # Add it to installed_flows table
    config.catchall_flow_installed_rule = RuleInfo()
    config.catchall_flow_installed_rule.sampling_config = config.catchall_sampling
    #config.installed_flows['*'] = config.catchall_flow_installed_rule

def LoadConfigFile(input_config_file_name):
    #config = Config()
    all_configs = []
    config = None
    common_config = None
    pcap_file_list_name = None

    input_config_file = open(input_config_file_name)

    for entry_line in input_config_file:

        if entry_line.lstrip().startswith("#"):
            # This is a commented line, so skip it
            #print "Skipping the comment line: " + entry_line.strip()
            continue

        entry_elements = entry_line.strip().split()

        if ((len(entry_elements) == 2) and (entry_elements[0] == "condition")):
            # Finalize previous config
            if config:
                FinalizeConfig(config)

            if (entry_elements[1] == "common"):
                # These are common configuration among all conditions, which may be overriden later on
                common_config = Config()
                config = common_config
            else:
                # This is a new condition
                config = Config(common_config, entry_elements[1])
                all_configs.append(config)

            continue

        elif ((len(entry_elements) != 3) or (entry_elements[1] != "=")):
            # Each line in the config file should have three parts, 
            # and the second part should be =. If this is not the caes
            # then skip this line.
            continue

        entry_name = entry_elements[0]
        entry_value = entry_elements[2]

        # Now set config entries based on provided options
        if entry_name == "installed_rule_sampling.sampling_rho":
            config.installed_rule_sampling.sampling_rho = int(entry_value)
        elif entry_name == "installed_rule_sampling.sampling_delta":
            config.installed_rule_sampling.sampling_delta = int(entry_value)
        elif entry_name == "installed_rule_sampling.sampling_m":
            config.installed_rule_sampling.sampling_m = int(entry_value)
        elif entry_name == "installed_rule_sampling.sampling_k":
            config.installed_rule_sampling.sampling_k = int(entry_value)
        elif entry_name == "installed_rule_sampling.sampling_alpha":
            config.installed_rule_sampling.sampling_alpha = float(entry_value)
        elif entry_name == "catchall_sampling.sampling_rho":
            config.catchall_sampling.sampling_rho = int(entry_value)
        elif entry_name == "catchall_sampling.sampling_delta":
            config.catchall_sampling.sampling_delta = int(entry_value)
        elif entry_name == "catchall_sampling.sampling_m":
            config.catchall_sampling.sampling_m = int(entry_value)
        elif entry_name == "catchall_sampling.sampling_k":
            config.catchall_sampling.sampling_k = int(entry_value)
        elif entry_name == "install_rule_sample_threshold":
            config.install_rule_sample_threshold = int(entry_value)
        elif entry_name == "maximum_flow_idle_time":
            config.maximum_flow_idle_time = int(entry_value)
        elif entry_name == "verbose_level":
            config.verbose_level = int(entry_value)
        elif entry_name == "prone_all_flows_info_interval":
            config.prone_all_flows_info_interval = int(entry_value)
        elif entry_name == "end_of_world_timestamp":
            config.end_of_world_timestamp = int(entry_value)
        elif entry_name == "log_directory":
            config.log_directory = entry_value
        elif entry_name == "log_file_prefix":
            config.log_file_prefix = entry_value
        elif entry_name == "log_file_id":
            config.log_file_id = entry_value
        elif entry_name == "log_file_extension":
            config.log_file_extension = entry_value
        elif entry_name == "pcap_file_list_name":
            pcap_file_list_name = entry_value
        elif entry_name == "log_sampled_packet_size":
            if (entry_value.lower() == "true"):
                config.log_sampled_packet_size = True
            else:
                config.log_sampled_packet_size = False
        elif entry_name == "idle_timeout_increasing_only":
            if (entry_value.lower() == "true"):
                config.idle_timeout_increasing_only = True
            else:
                config.idle_timeout_increasing_only = False
        elif entry_name == "log_sampled_packet_interarrival_time":
            if (entry_value.lower() == "true"):
                config.log_sampled_packet_interarrival_time = True
            else:
                config.log_sampled_packet_interarrival_time = False
        elif entry_name == "log_sampled_packet_tcp_flag":
            if (entry_value.lower() == "true"):
                config.log_sampled_packet_tcp_flag = True
            else:
                config.log_sampled_packet_tcp_flag = False
        elif entry_name == "log_sampled_packet_tcp_sqn":
            if (entry_value.lower() == "true"):
                config.log_sampled_packet_tcp_sqn = True
            else:
                config.log_sampled_packet_tcp_sqn = False
        elif entry_name == "packet_id_generation":
            if (entry_value.lower() == "wandisp"):
                config.GeneratePacketID = GeneratePacketIDWANDISPDataset
            elif (entry_value.lower() == "lowerport"):
                config.GeneratePacketID = GeneratePacketIDLowerPort
            elif (entry_value.lower() == "asis"):
                config.GeneratePacketID = GeneratePacketIDAsIs
            elif (entry_value.lower() == "asisraw"):
                config.GeneratePacketID = GeneratePacketIDAsIsRaw
            else:
                config.GeneratePacketID = GeneratePacketIDAsIs
        elif entry_name == "packet_processing":
            if (entry_value.lower() == "dynamic_heavy_hitter_detection"):
                config.ProcessPacket = ProcessPacketDynamicHHDetection
            elif (entry_value.lower() == "light_heavy_hitter_detection"):
                config.ProcessPacket = ProcessPacketLightHHDetection
            else:
                config.ProcessPacket = ProcessPacketLightHHDetection
        elif entry_name == "sampled_packet_processing":
            if (entry_value.lower() == "dynamic_heavy_hitter_detection"):
                config.ProcessSampledPacket = ProcessSampledPacketDynamicHHDetection
            elif (entry_value.lower() == "light_heavy_hitter_detection"):
                config.ProcessSampledPacket = ProcessSampledPacketLightHHDetection
            elif (entry_value.lower() == "estimate_idle_timeout"):
                config.ProcessSampledPacket = ProcessSampledPacketEstimateIdleTimeout
            elif (entry_value.lower() == "estimate_idle_timeout_consecutive_packets"):
                config.ProcessSampledPacket = ProcessSampledPacketEstimateIdleTimeoutConsecutivePackets
            elif (entry_value.lower() == "record_sampled_packet_only"):
                config.ProcessSampledPacket = ProcessSampledPacketRecordOnly
            elif (entry_value.lower() == "idle_timeout_basedon_flow_size"):
                config.ProcessSampledPacket = ProcessSampledPacketIdleTimeoutBasedOnFlowSize
                config.UpdateIdleTimeout = UpdateIdleTimeoutBasedOnFlowSize
            elif (entry_value.lower() == "idle_timeout_basedon_flow_size_inter_arrival_time"):
                config.ProcessSampledPacket = ProcessSampledPacketIdleTimeoutBasedOnFlowSize
                config.UpdateIdleTimeout = UpdateIdleTimeoutBasedOnFlowSizeAndPacketInterArrivalTimes
                config.SetInitialIdleTimeout = SetInitialIdleTimeoutBasedOnPacketInterArrivalTimes
            elif (entry_value.lower() == "idle_timeout_constant"):
                config.ProcessSampledPacket = ProcessSampledPacketRecordOnly
                config.UpdateIdleTimeout = UpdateIdleTimeoutUnchanged
                config.SetInitialIdleTimeout = SetInitialIdleTimeoutConstant
            else:
                config.ProcessSampledPacket = ProcessSampledPacketRecordOnly
                config.UpdateIdleTimeout = UpdateIdleTimeoutUnchanged
                config.SetInitialIdleTimeout = SetInitialIdleTimeoutConstant
        elif entry_name == "show_statistics_type":
            if (entry_value.lower() == "nothing"):
                config.ShowStatistics = ShowStatisticsNothing
            elif (entry_value.lower() == "rule_table_occupancy"):
                config.ShowStatistics = ShowStatisticsRuleTableOccupancy
            else:
                config.ShowStatistics = ShowStatisticsNothing
        elif entry_name == "show_statistics_interval":
            config.show_statistics_interval = float(entry_value)
        elif entry_name == "rule_install_delay":
            config.rule_install_delay = float(entry_value)
        elif entry_name == "rule_install_delay_first":
            config.rule_install_delay_first = float(entry_value)
        elif entry_name == "rule_timeout_idle_beta":
            config.rule_timeout_idle_beta = float(entry_value)
        elif entry_name == "rule_timeout_hard_gamma":
            config.rule_timeout_hard_gamma = float(entry_value)
        elif entry_name == "rule_timeout_idle":
            config.rule_timeout_idle = float(entry_value)
        elif entry_name == "rule_timeout_hard":
            config.rule_timeout_hard = float(entry_value)
        elif entry_name == "rule_timeout_idle_min":
            config.rule_timeout_idle_min = float(entry_value)
        elif entry_name == "rule_timeout_idle_max":
            config.rule_timeout_idle_max = float(entry_value)
        elif entry_name == "rule_timeout_idle_zeta":
            config.rule_timeout_idle_zeta = float(entry_value)
        elif entry_name == "rule_timeout_idle_theta":
            config.rule_timeout_idle_theta = float(entry_value)
        elif entry_name == "eviction_policy":
            if (entry_value.lower() == "evict_least_recently_used"):
                config.EvictRule = EvictRuleLRU
            elif (entry_value.lower() == "evict_least_frequently_used"):
                config.EvictRule = EvictRuleLFU
            elif (entry_value.lower() == "evict_longest_estimated_next_packet_arrival"):
                config.EvictRule = EvictRuleLongestEstimatedNextPacketArrival
            else:
                config.EvictRule = EvictRuleLRU
        elif entry_name == "flow_table_maximum_size":
            config.flow_table_maximum_size = int(entry_value)
        else:
            print "Invalid config entry \"%s\" with value \"%s\"" % (entry_name, entry_value)

    input_config_file.close()

    # Finalize previous config
    if config:
        FinalizeConfig(config)

    return all_configs, common_config, pcap_file_list_name

def ReadListFile(list_file_name):
    list_file = open(list_file_name)

    file_list = []
    for entry in list_file:
        file_list.append(entry.strip())

    return file_list

def Main(input_config_file_name):
    # This is the main fucntion that runs everything!

    #all_flows_info = {}
    #config = Config()
    #config = LoadConfigFile(input_config_file_name)
    
    #all_configs = []
    #all_configs.append(LoadConfigFile('./testrun/flexamsimul-config01.txt'))
    #all_configs.append(LoadConfigFile('./testrun/flexamsimul-config02.txt'))

    all_configs, common_config, pcap_file_list_name = LoadConfigFile(input_config_file_name)
    #return

    pcap_file_list = ReadListFile(pcap_file_list_name)

    # Process all pcap files in the list
    for pcap_file_name in pcap_file_list:
        ProcessPCAPFile(pcap_file_name, all_configs)

    for config in all_configs:
        #ProneAllFlowsInfo(config, config.end_of_world_timestamp)
        FlushAllRemainingFlowsInfo(config)
        PrintFlowInfo(config.catchall_flow, config)
        #print "There are " + str(len(config.all_flows_info)) +  " active flows remaining in config " + str(config.config_id)
        # Close log file
        config.log_file.close()

if __name__ == '__main__':
    if (len(sys.argv) != 2):
        print "Wrong arguments. \nUsage: " + str(sys.argv[0]) + " config_file_name"
        sys.exit()

    config_file_name = sys.argv[1]
    #Main('./testrun/samplepcaplist3.txt', './testrun/flexamsimul-config03.txt')
    Main(config_file_name)

