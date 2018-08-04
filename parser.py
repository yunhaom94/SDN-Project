#!/usr/bin/python3

# Parser will read the pcap file

import dpkt
import socket
from datetime import datetime
from switch import Switch
import os
from helpers import Output
import argparse
import configparser
import time




class Config():
    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        
    def parse_config_file(self):

        self.config = configparser.ConfigParser(inline_comment_prefixes="#")
        self.config.read(self.config_file_path)
        self.verify_config()

        self.trace_path = self.config["COMMON"]["trace_path"]

        self.num_switches = 9999 # default number is 9999
        if self.config.has_option("COMMON", "num_switches"):
            self.num_switches = int(self.config["COMMON"]["num_switches"])


        self.reference_on = False
        if self.config.has_option("COMMON", "reference_on"):
            self.reference_on = self.config["COMMON"].getboolean("reference_on")



    def verify_config(self):
        if self.config:
            if "COMMON" not in self.config.sections():
                raise Exception("No COMMON section in config file")

            if not self.config.has_option("COMMON", "trace_path"):
                raise Exception("trace_path option must exists in COMMON section")


    def create_switches(self):
        '''
        Create switches with definition in the config file
        '''

        switches = []
        for name in self.config.sections():
            if name != "COMMON":
                sid = name
                
                other_options = dict(self.config.items(sid, vars))

                if self.config.has_option(name, "active"):
                    del other_options["active"]
                    if not self.config[name].getboolean("active"):
                        continue
                 
                if not self.config.has_option(name, "timeout"):
                    raise Exception("switch doesn't have timeout set")

                del other_options["timeout"]
                timeout = int(self.config[name]["timeout"])
                
                to_file = True
                if self.config.has_option(name, "to_file"):
                    del other_options["to_file"]
                    to_file = self.config[name].getboolean("to_file")

                sw = Switch(sid, timeout, to_file, **other_options)
                switches.append(sw)

                if len(switches) > self.num_switches:
                    break


        return switches
            


# read the pcap file and converted into useable structure
def process_pcap_file(pcap_file_name, switches):
    pcap_file_handler = open(pcap_file_name, "rb")
    pcap_file = dpkt.pcap.Reader(pcap_file_handler)
    
    f_size = os.stat(pcap_file_name).st_size
    count = 1

    for timestamp, buf in pcap_file:
        for sw in switches:
            #sw.process_packet(timestamp, buf)
            pos = pcap_file_handler.tell()

        print("Progress: {0:.0%}".format(pos/f_size), end="\r", flush=True)


        #count += 1
        

def main(config_file):
    config = Config(config_file)
    config.parse_config_file()
    switches = config.create_switches()

    path = config.trace_path

    if config.reference_on:
        ref_switch = Switch("reference", 1000000, True)
        switches.append(ref_switch)

    total_file = len([file for file in os.listdir(path) if os.path.splitext(file)[1].lower() == ".pcap"])
    parsed_file_count = 1

    #TODO: This part can be paralleled by putting each switch into different threads
    for file in os.listdir(path):
        ext = os.path.splitext(file)[1]

        if ext.lower() == ".pcap":
            full_path = path + file
            print("#################\nParsing {path}: file {i} of total {total}"
            .format(path=full_path, i=parsed_file_count, total=total_file))
            start = time.time()

            process_pcap_file(full_path, switches)

            end = time.time()

            print(full_path + " Completed in " + str(end - start) + " seconds" )
            parsed_file_count += 1
        
        #break

    for sw in switches:
        print(sw.output_all_flow())


    print("=====ALL TRACE FILES PARSED=====")
    
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

# TODO: 
