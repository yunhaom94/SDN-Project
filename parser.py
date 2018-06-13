#!/usr/bin/python3

# Parser will parse the pcap file

import dpkt
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


# read the pcap file and converted into readable structure
def process_pcap_file(pcap_file_name):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    for timestamp, buf in pcap_file:
        print(datetime.utcfromtimestamp(timestamp))

        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: FROM: ' + mac_addr(eth.src) + " TODO: " + mac_addr(eth.dst) + " TYPE: " + str(eth.type))

    return


def main():
    process_pcap_file("./tracefiles/univ1_pt1")
    return 



if __name__ == '__main__':
    main()

