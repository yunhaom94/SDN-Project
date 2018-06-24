#!/usr/bin/python3

# Parser will read the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch

# read the pcap file and converted into useable structure
def process_pcap_file(pcap_file_name):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    switch_1 = Switch()

    count = 1

    for timestamp, buf in pcap_file:
        #print("AT: " + str(count))
        switch_1.process_packet(timestamp, buf)
        
        count += 1
        

        

def main():
    process_pcap_file("./tracefiles/trace.pcap")
    return 


if __name__ == '__main__':
    main()

'''
TODO: 
1. Multiple files
'''