#!/usr/bin/python3

# Parser will read the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch
import os
from helpers import Output
import argparse




class Config():
    _COMMON_OPTIONS = [
        "trace_path",
        "num_switches",
        "dump_interval"
        
    ]

    _SWITCH_OPTIONS = [
        "timeout",
        "id",
        "active",
        "to_file" 
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
            num_switches = 9999 #if not provide, just parse all conditions
        except ValueError:
            raise Exception("num_switches provided is not a number!")
        
        Output.VERBOSE("a total number of " + str(num_switches) + " switches will be created")

        for k, v in settings.items():
            if num_switches <= 0:
                break
            
            if k not in Config._COMMON_OPTIONS:
                if "id" in v.keys():
                    sid = v["id"]
                else:
                    sid = k

                to_file = False
                
                if "to_file" in v.keys():
                    if v["to_file"].strip().lower() == "true":
                        to_file = True

                    


                timeout = int(v["timeout"])
                switch = Switch(sid, timeout, to_file)
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
        

def main(config_file):
    settings = Config.parse_config_file(config_file)

    switches = Config.create_switches(settings)
    path = settings["trace_path"]


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
    parser = argparse.ArgumentParser(description="SDN Switch Simulator")
    parser.add_argument("config_file", help="Path to config file")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity",
                    action="store_true")
    parser.add_argument("-d" ,"--debug", help="Show debug messages",
                    action="store_true")

    args = parser.parse_args()
    config_file = args.config_file
    Output.VERBOSE_ON = args.verbose
    Output.DEBUG_ON = args.debug

    main(config_file)

