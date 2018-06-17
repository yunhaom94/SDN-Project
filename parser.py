#!/usr/bin/python3

# Parser will parse the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch

# read the pcap file and converted into useable structure
def process_pcap_file(pcap_file_name):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    switch_1 = Switch()

    count = 0

    for timestamp, buf in pcap_file:
        switch_1.process_packet(timestamp, buf)
        if count == -1:
            break
        count += 1
        

def main():
    process_pcap_file("./tracefiles/univ1_pt1")
    return 


if __name__ == '__main__':
    main()

