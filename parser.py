#!/usr/bin/python3

# Parser will read the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch
import os
from helpers import *




class Config():
    _COMMON_OPTIONS = [
        "trace_path",
         "num_switches",
         "dump_interval"
        
    ]

    _SWITCH_OPTIONS = [
        "timeout"
    ]


    def __init__(self):
        self.trace_file_path = None
        self.num_switches = 0
        self.switches = []


    @staticmethod
    def parse_config_file(config_file_path):

        settings = {}

        with open(config_file_path, "r") as fp:
            line = fp.readline()

            in_block = None

            while line:
                # if comment
                if line[0] == '#':
                    line = fp.readline()
                    continue    

                line = line.split('#')[0].lower() # if comment in the back
                # common settings

                if not in_block:
                    option = line.split("=")
                    if option[0].strip() in Config._COMMON_OPTIONS:
                        settings[option[0]] = option[1].strip()
                        line = fp.readline()
                        continue
                    

                elif in_block:
                    option = line.split("=")
                    if option[0].strip() in Config._SWITCH_OPTIONS:
                        settings[in_block][option[0]]  = option[1].strip()
                        line = fp.readline()
                        continue

                if line.split("_")[0].strip() == "condition" and line.split("_")[1].strip() != "end":
                    if not in_block:
                        in_block = "switch_" + line.split("_")[1].strip()
                        settings[in_block] = {}
                        line = fp.readline()
                        continue
                    else:
                        raise Exception("Config: block not closed")

                    
                
                if line.strip() == "condition_end":
                    if in_block:
                        in_block = None  
                        line = fp.readline()
                        continue
                    else:
                        raise Exception("Config: not in block")
                
                line = fp.readline()
                continue

        return settings
                
    @staticmethod
    def create_switches(settings):
        switches = []
        try:
            num_switches = int(settings['num_switches'])
        except KeyError:
            num_switches = 1
        except ValueError:
            raise Exception("num_switches provided is not a number!")
        
        VERBOSE("a total number of " + str(num_switches) + " switches will be created")

        for k, v in settings.items():
            if num_switches <= 0:
                break
            
            if 'switch_' in k:
                timeout = int(v["timeout"])
                switch = Switch(timeout)
                switches.append(switch)
                num_switches -= 1

        return switches
            


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
    #switch_1 = Switch(100)

    config_file = "config_example.txt"
    settings = Config.parse_config_file(config_file)
    switches = Config.create_switches(settings)

    for file in os.listdir(path):
        ext = os.path.splitext(file)[1]

        if ext.lower() == ".pcap":
            full_path = path + file
            print("Processing " + full_path)
            #process_pcap_file(full_path, switch_1)
            for sw in switches:
               process_pcap_file(full_path, sw)
        
    print("Done")
    
    return 


if __name__ == '__main__':
    main()

'''
TODO: 
1. Multiple files
'''