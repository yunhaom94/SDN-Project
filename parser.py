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
        "timeout",
        "id"
    ]


    def __init__(self):
        self.trace_file_path = None
        self.num_switches = 0
        self.switches = []


    @staticmethod
    def parse_config_file(config_file_path):

        settings = {}

        i = 0

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
                        settings[i][option[0]]  = option[1].strip()
                        line = fp.readline()
                        continue

                if line.strip() == "condition":
                    if not in_block:
                        in_block = True
                        settings[i] = {}
                        line = fp.readline()
                        continue
                    else:
                        raise Exception("Config: block not closed")

                    
                
                if line.strip() == "condition_end":
                    if in_block:
                        in_block = False  
                        line = fp.readline()
                        i = i + 1
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
            
            if k not in Config._COMMON_OPTIONS:
                if "id" in v.keys():
                    sid = v["id"]
                else:
                    sid = k

                timeout = int(v["timeout"])
                switch = Switch(sid, timeout)
                switches.append(switch)
                num_switches -= 1

        return switches
            


# read the pcap file and converted into useable structure
def process_pcap_file(pcap_file_name, switch):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)

    count = 1

    for timestamp, buf in pcap_file:

        switch.process_packet(timestamp, buf)
        
        #count += 1
        

        

def main():
    path = "./tracefiles/"

    config_file = "config_example.txt"
    settings = Config.parse_config_file(config_file)
    print(settings)

    switches = Config.create_switches(settings)


    for file in os.listdir(path):
        ext = os.path.splitext(file)[1]

        if ext.lower() == ".pcap":
            full_path = path + file
            print("Processing " + full_path)
           
            for sw in switches:
               process_pcap_file(full_path, sw)
        
        #break
    print("Done")
    
    return 


if __name__ == '__main__':
    main()

'''
TODO: 
1. Multiple files
'''