#!/usr/bin/python3

# Parser will read the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch
import os

# read the pcap file and converted into useable structure
def process_pcap_file(pcap_file_name, switch):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    

    count = 1

    for timestamp, buf in pcap_file:
        #print("AT: " + str(count))
        switch.process_packet(timestamp, buf)
        
        count += 1
        

        

def main():
    path = "./tracefiles/"
    switch_1 = Switch()


    for file in os.listdir(path):
        ext = os.path.splitext(file)[1]

        if ext.lower() == ".pcap":
            full_path = path + file
            print("Processing " + full_path)
            process_pcap_file(full_path, switch_1)
        
    
    
    return 


if __name__ == '__main__':
    main()

'''
TODO: 
1. Multiple files
'''