'''
Parse the simulator switch's outputs
features:

'''
import argparse
import csv
import os
import parser as switch_parser

import matplotlib.pyplot as plt
import numpy as np


def plot(x, y, name, linestyle='.'):
    # Plot the figure
    fig, ax = plt.subplots()
    ax.plot(x, y, linestyle)
    mean = np.mean(y)
    median = np.median(y)
    flow_95 = np.percentile(y, 95)
    flow_99 = np.percentile(y, 99)

    ax.axhline(mean, color='r', linestyle='--', label='Mean: %.3f' % mean)
    ax.axhline(median, color='m', linestyle='--', label='Median: %.3f' % median)
    ax.axhline(flow_95, color='g', linestyle='--', label='95: %.3f' % flow_95)
    ax.axhline(flow_99, color='k', linestyle='--', label='99: %.3f' % flow_99)

    # Coniguration
    # box = ax.get_position()
    # ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])
    if name == 'Flow':
        ax.legend(loc='upper right', fontsize='small', framealpha=0)
    else:
        ax.legend(loc='center right', fontsize='small', framealpha=0)
    plt.ylabel(name)
    plt.xlabel('time')
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
    header = ["time", "total_packets", "active_flows", "hit_rate", "cache_size"]
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
    all_cache_size = []

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
            elif order == 9:
                tracking_values["cache_size"] = value
                all_cache_size.append(float(value))
        order += 1

        if line.strip() == "*":
            time += interval
            all_time.append(time)
            order = 0
            writer.writerow(tracking_values)
            tracking_values["time"] = time
    
    # Delete first item:
    all_time = all_time[1:]
    all_packets = all_packets[1:]
    all_active_flows = all_active_flows[1:]
    all_hit_rate = all_hit_rate[1:]
    if len(all_cache_size) != 0: 
        plot(all_time, all_cache_size, "Cache")
        plt.savefig(dir_name + '/' + 'cache')

    # Plot
    plot(all_time, all_active_flows, "Flow")
    plt.savefig(dir_name + '/' + 'flow')
    plot(all_time, all_hit_rate, "Hit Rate", linestyle='-')
    plt.savefig(dir_name + '/' + 'hit_rate')
    plt.close('all')

    csv_fp.close()
    return [all_time, all_active_flows, all_hit_rate]

def parse_all(all_info, file_cat, times):
    """
    all_info: list of [all_time, all_active_flows, all_hit_rate]
    file_cat: list of switches' categories
    times: list of switches' timeouts
    """
    # MIGHT CHANGE:
    # Each category contains all infomation
    categories = {'no_rule': [],
                    'parallel_timeout': [],
                    'recycle_random': [],
                    'recycle_fifo': []
                    }

    # Create a directory to contain plots and information
    dir_name = 'all_result_dir'
    try:
        os.mkdir(dir_name)
    except:
        print("Cannot mkdir")

    for i in range(len(file_cat)):
        categories.get(file_cat[i], 'no_rule').append(i)

    # For each category, need:
    # x-axis: timeout
    # y-axis: avg, median, 95, 99 of hit-rate, flows
    for cur_cat in categories.keys():
        timeout = []
        info = {'mean': [],
                'median': [],
                '95': [],
                '99': []}
        
        
        for i in categories[cur_cat]:
            timeout.append(times[i])

            # element in info[''] is [flow, hit_rate]
            info['mean'].append( [np.mean(all_info[i][1]), np.mean(all_info[i][2])] )
            info['median'].append( [np.median(all_info[i][1]), np.median(all_info[i][2])] )
            info['95'].append( [np.percentile(all_info[i][1], 95), np.percentile(all_info[i][2], 95)] )
            info['99'].append( [np.percentile(all_info[i][1], 99), np.percentile(all_info[i][2], 99)] )
            
            # Plot the flow
            fig, ax = plt.subplots()
            for stats in info.keys():
                flow_info = [i[0] for i in info[stats]]
                ax.plot(timeout, flow_info, label=stats, marker='o')

            ax.legend(loc='upper left', shadow=True)
            ax.grid(True)
            plt.ylabel("Flow occupancy")
            plt.xlabel("Time out")
            plt.title(cur_cat)
            plt.savefig(dir_name + '/' + cur_cat+ '_flow')
            plt.close('all')

            # Plot the hr
            fig, ax = plt.subplots()
            for stats in info.keys():
                hr_info = [i[1] for i in info[stats]]
                ax.plot(timeout, hr_info, label=stats, marker='o')

            ax.legend(loc='upper left', shadow=True)
            ax.grid(True)
            plt.ylabel("Hit rate")
            plt.title(cur_cat)
            plt.xlabel("Time out")
            plt.savefig(dir_name + '/' + cur_cat+ '_hr')
            plt.close('all')

        categories[cur_cat] = info

    # For all, need:
    # x-axis: hit-rate
    # y-axis: flow occupancy
    # plot of different methods' avg performance
    for stats_cat in {'mean', 'median', '95', '99'}:
        fig, ax = plt.subplots()
        for cur_cat in categories.keys():
            x = [i[1] for i in categories[cur_cat][stats_cat]]
            y = [i[0] for i in categories[cur_cat][stats_cat]]
            ax.plot(x, y, label=cur_cat, marker='o')

        ax.legend(loc='upper left', shadow=True)
        ax.grid(True)
        plt.ylabel("Flow occupancy")
        plt.xlabel("Hit rate")
        plt.title("Summary")
        plt.savefig(dir_name + '/' + stats_cat +'_Summary')
        plt.close('all')






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
