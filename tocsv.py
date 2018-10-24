import argparse
import csv
import os
import parser as switch_parser
import matplotlib.pyplot as plt
import numpy as np

def parse(file_name, file_cate, file_to):
    # Read the file
    try:
        in_fp = open(file_name, "r", encoding="utf-8")
    except:
        print("Invalid file input")
        return

    # Create a directory to contain plots and information
    
    # Create the result csv file:
    csv_name = file_name + ".csv"
    csv_fp = open(csv_name, "w+", newline='')
    header = ["time", "total_packets", "active_flows", "hit_rate", "cache_size", "cache_hit"]
    writer = csv.DictWriter(csv_fp, delimiter=",", fieldnames=header)
    writer.writeheader()

    # Init parameters
    time = 0
    interval = 0
    order = -1 # line number
    tracking_values = {}
    tracking_values["time"] = time

    all_time = np.array([])
    all_packets = np.array([])
    all_active_flows = np.array([])
    all_hit_rate = np.array([])
    all_cache_size = np.array([])
    cache_hit = np.array([])

    # Parse information
    for line in in_fp:
        content = line.split(":")

        if len(content) == 2:
            value = content[1].strip()
            if order == 1:
                tracking_values["total_packets"] = value
                all_packets = np.append(all_packets, float(value))
            elif order == 3:
                tracking_values["active_flows"] = value
                all_active_flows = np.append(all_active_flows, float(value))
            elif order == 6:
                tracking_values["hit_rate"] = value
                all_hit_rate = np.append(all_hit_rate, float(value))
            elif time == 0 and order == 2:
                interval = int(value) if int(value) < 100 else 100
            elif order == 9:
                tracking_values["cache_size"] = value
                all_cache_size = np.append(all_cache_size, float(value))
            elif order == 10:
                tracking_values["cache_hit"] = value
                cache_hit = np.append(cache_hit, float(value))

        order += 1

        if line.strip() == "*":
            all_time = np.append(all_time, time)
            time += interval
            order = 0
            writer.writerow(tracking_values)
            tracking_values["time"] = time

    # All set
    csv_fp.close()

if __name__ == '__main__':
    # Get the user input
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('config_file', help="config file")
    args = arg_parser.parse_args()
    config_file = args.config_file

    # Initialize
    pathes = []
    file_cat = []
    times = []
    num_switches = 0

    # Parse the config file
    config_instance = switch_parser.Config(config_file)
    config_instance.parse_config_file()
    config = config_instance.config

    # Save to 'data' folder:
    try:
        os.mkdir('data')
    except:
        print("Cannot mkdir")

    for name in config.sections():
        if name != "COMMON":
            sid = name
            # Might be useful in the future
            other_options = dict(config.items(sid, vars))

            if config.has_option(name, "active"):
                if not config[name].getboolean("active"):
                    continue

            num_switches += 1

            timeout = int(config[name]["timeout"])

            to_file = True
            if config.has_option(name, "to_file"):
                to_file = config[name].getboolean("to_file")
                if not to_file:
                    continue
            
            if config.has_option(name, "rule"):
                rule_name = config[name]["rule"]
                multiplier = ""
                if config.has_option(name, "cache_timeout_multiplier"):
                    multiplier = config[name]["cache_timeout_multiplier"]
                file_cat.append(rule_name + multiplier)
            else:
                file_cat.append("no_rule")

            # Current switch has output file with path: "log_"+sid, timeout: timeout, rule: other_opetions
            pathes.append("log_" + sid)
            times.append(timeout)
            
            if num_switches > config_instance.num_switches:
                break
    
    # Parse single file:
    print("======================")
    all_info = []
    for i in range(len(pathes)):
        print("Parsing " + pathes[i] )
        all_info.append(parse(pathes[i], file_cat[i], int(times[i])))
        print("Finish parsing this file.")
        print("======================")
