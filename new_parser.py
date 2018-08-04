'''
Parse the simulator switch's outputs
features:

'''
import argparse
import csv
import numpy as np
import matplotlib.pyplot as plt
import os
import parser as switch_parser

def plot(x, y, name, linestyle='.'):
    # Plot the figure
    fig, ax = plt.subplots()
    ax.plot(x, y, linestyle, label=name)
    mean = np.mean(y)
    median = np.median(y)
    flow_95 = np.percentile(y, 95)
    flow_99 = np.percentile(y, 99)

    ax.axhline(mean, color='k', linestyle='--', label='Mean: '+str(mean))
    ax.axhline(median, color='k', linestyle='--', label='Median: '+str(median))
    ax.axhline(flow_95, color='k', linestyle='--', label='95%: '+str(flow_95))
    ax.axhline(flow_99, color='k', linestyle='--', label='99%: '+str(flow_99))

    # Coniguration
    ax.legend(loc='upper right', shadow=True)
    plt.ylabel(name)
    plt.title(name)


def parse(file_name, file_cate, file_to):
    try:
        in_fp = open(file_name, "r", encoding="utf-8")
    except:
        print("Invalid file input")
        return

    # Create a directory to contain plots and information
    dir_name = file_cate + str(file_to) + '_dir'
    try:
        os.mkdir(dir_name)
    except:
        print("Cannot mkdir")

    # Create the result csv file:
    csv_name = dir_name + '/' +  "parsed.csv"
    csv_fp = open(csv_name, "w+", newline='')
    header = ["time", "total_packets", "active_flows", "hit_rate"]
    writer = csv.DictWriter(csv_fp, delimiter=",", fieldnames=header)
    writer.writeheader()

    # Set parameters:
    time = 0
    interval = 0
    order = 0 # line number
    tracking_values = {}
    tracking_values["time"] = time

    all_time = []
    all_packets = []
    all_active_flows = []
    all_hit_rate = []

    # Parse information
    for line in in_fp:
        content = line.split(":")

        if len(content) == 2:
            value = content[1].strip()
            if order == 1:
                tracking_values["total_packets"] = value
                all_packets.append(float(value))
            if order == 3:
                tracking_values["active_flows"] = value
                all_active_flows.append(float(value))
            elif order == 6:
                tracking_values["hit_rate"] = value
                all_hit_rate.append(float(value))
            elif time == 0 and order == 2:
                interval = int(value) if int(value) < 100 else 100

        order += 1

        if line.strip() == "*":
            time += interval
            all_time.append(time)
            order = 0
            writer.writerow(tracking_values)
            tracking_values["time"] = time

    # Plot
    plot(all_time, all_active_flows, "Hit Rate")
    plt.savefig(dir_name + '/' + 'flow')
    plot(all_time, all_hit_rate, "Hit Rate", linestyle='-')
    plt.savefig(dir_name + '/' + 'hit_rate')

    csv_fp.close()
    return [all_time, all_active_flows, all_hit_rate]

def parse_all(all_info, file_cat, times):
    # MIGHT CHANGE:
    # Each category contains all infomation
    no_rule = []
    parallel = []
    random = []
    fifo = []

    for i in range(len(file_cat)):
        my_category = {'no_rule': no_rule,
                       'parallel_timeout': parallel,
                       'recycle_random': random,
                       'recycle_fifo': fifo
                       }.get(file_cat[i], 'no_rule')
        my_category.append(i)

    print(no_rule)






if __name__ == '__main__':
    # Get the user input
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('config_file', help="config file")
    args = arg_parser.parse_args()
    config_file = args.config_file

    # Parse the config file
    config_instance = switch_parser.Config(config_file)
    config_instance.parse_config_file()
    config = config_instance.config
    
    pathes = []
    file_cat = []
    times = []
    num_switches = 0

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
                file_cat.append(config[name]["rule"])
            else:
                file_cat.append("no_rule")

            # Current switch has output file with path: "log_"+sid, timeout: timeout, rule: other_opetions
            pathes.append("log_" + sid)
            times.append(timeout)
            
            if num_switches > config_instance.num_switches:
                break
    
    # Start analyze data outputs:
    print("======================")
    all_info = []
    for i in range(len(pathes)):
        print("Parsing " + pathes[i] )
        all_info.append(parse(pathes[i], file_cat[i], int(times[i]) ))
        print("Finish parsing this file.")
        print("======================")
    
    print("Parsing all information: ")
    parse_all(all_info, file_cat, times)
    print("Done. GL")
