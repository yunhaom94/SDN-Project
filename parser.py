#!/usr/bin/python3

# Parser will parse the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch

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


# read the pcap file and converted into useable structure
def process_pcap_file(pcap_file_name):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    switch = Switch()

    for timestamp, buf in pcap_file:
        switch.process_packet(timestamp, buf)
        

def main():
    process_pcap_file("./tracefiles/univ1_pt1")
    return 



if __name__ == '__main__':
    main()

