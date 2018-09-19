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


def plot(x, y, name, linestyle='-'):
    # Plot the figure
    fig, ax = plt.subplots()
    fig.set_size_inches(15, 10)
    ax.plot(x, y, linestyle)

    # Adding horizontal lines
    mean = np.mean(y)
    median = np.median(y)
    flow_95 = np.percentile(y, 95)
    flow_99 = np.percentile(y, 99)

    ax.axhline(mean, color='r', linestyle='--', label='Mean: %.3f' % mean)
    ax.axhline(median, color='m', linestyle='--', label='Median: %.3f' % median)
    ax.axhline(flow_95, color='g', linestyle='--', label='95: %.3f' % flow_95)
    ax.axhline(flow_99, color='k', linestyle='--', label='99: %.3f' % flow_99)

    # Adding legends and label
    if 'Rate' in name:
        ax.legend(loc='center right', fontsize='large', framealpha=0)
    else:
        ax.legend(loc='upper right', fontsize='large', framealpha=0)
    plt.ylabel(name)
    plt.xlabel('time')
    plt.title(name)


def parse(file_name, file_cate, file_to):
    # Read the file
    try:
        in_fp = open(file_name, "r", encoding="utf-8")
    except:
        print("Invalid file input")
        return

    # Create a directory to contain plots and information
    dir_name = 'data/' + file_cate + str(file_to) + '_dir'
    try:
        os.mkdir(dir_name)
    except:
        print("Cannot mkdir")

    # Create the result csv file:
    csv_name = dir_name + '/' +  "parsed.csv"
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
    
    # Delete first several items:
    opt_out = len(all_time) // 100 * 5
    all_time = all_time[opt_out:]
    all_packets = all_packets[opt_out:]
    all_active_flows = all_active_flows[opt_out:]
    all_hit_rate = all_hit_rate[opt_out:]

    # Plot
    plot(all_time, all_active_flows, "Flow")
    plt.savefig(dir_name + '/' + 'flow')
    plot(all_time, all_hit_rate, "Hit Rate", linestyle='-')
    plt.savefig(dir_name + '/' + 'hit_rate')

    # Handle cache's info
    if len(all_cache_size) != 0: 
        all_cache_size = all_cache_size[opt_out:]
        plot(all_time, all_cache_size, "Cache")
        plt.savefig(dir_name + '/' + 'cache')

        cache_hit = cache_hit[opt_out:]
        plot(all_time, cache_hit, "Cache Hit Rate", linestyle='-')
        plt.savefig(dir_name + '/' + 'cache_hit_rate')

        # Plot summary of cache and flow table: TODO: MIGHT CHANGE in the future
        all_active_flows = all_cache_size + all_active_flows
        plot(all_time, all_active_flows, "Sum Flow Occupancy")
        plt.savefig(dir_name + '/' + 'sum_flow')


    # All set
    plt.close('all')
    csv_fp.close()
    return [all_time, all_active_flows, all_hit_rate]

def parse_all(all_info, file_cat, times, linear=False):
    """
    all_info: list of [all_time, all_active_flows, all_hit_rate]
    file_cat: list of switches' categories
    times: list of switches' timeouts
    """
    # TODO: MIGHT CHANGE:
    # Each category contains all infomation
    categories = {'no_rule': [],
                    'cache_1p5x': [],
                    'cache_5x': [],
                    'cache_10x': [],
                    'cache_dynamic_timeout_last_rules':[],
                    'smart_time': []
                    }

    for i in range(len(file_cat)):
        categories[file_cat[i]].append(i)

    # Create a directory to contain plots and information
    dir_name = 'all_result_dir'
    try:
        os.mkdir(dir_name)
    except:
        print("Cannot mkdir")

    # For each category, need:
    # x-axis: timeout
    # y-axis: avg, median, 95, 99 of hit-rate, flows
    for cur_cat in categories.keys():
        timeout = []
        info = {'mean': [],
                'median': [],
                '95': [],
                '99': [],
                'max': []}
        
        
        for i in categories[cur_cat]:
            timeout.append(times[i])

            # element in info[''] is [flow, hit_rate]
            info['mean'].append( [np.mean(all_info[i][1]), np.mean(all_info[i][2])] )
            info['median'].append( [np.median(all_info[i][1]), np.median(all_info[i][2])] )
            info['95'].append( [np.percentile(all_info[i][1], 95), np.percentile(all_info[i][2], 95)] )
            info['99'].append( [np.percentile(all_info[i][1], 99), np.percentile(all_info[i][2], 99)] )
            info['max'].append( [np.max(all_info[i][1]), np.mean(all_info[i][2])] )

            # Plot the flow
            fig, ax = plt.subplots()
            fig.set_size_inches(20, 15)
            for stats in info.keys():
                flow_info = [i[0] for i in info[stats]]
                if linear:
                    ax.plot(timeout, flow_info, label=stats, marker='.')
                else:
                    ax.semilogx(timeout, flow_info, label=stats, marker='.', basex=10)


            # Adding legend and label
            ax.legend(loc='upper left', shadow=True)
            ax.grid(which='both')
            plt.ylabel("Flow occupancy")
            plt.xlabel("Time out")
            plt.title(cur_cat)
            plt.savefig(dir_name + '/' + cur_cat+ '_flow')
            plt.close('all')

            # Plot the hr
            fig, ax = plt.subplots()
            fig.set_size_inches(20, 15)
            for stats in info.keys():
                hr_info = [i[1] for i in info[stats]]
                if linear:
                    ax.plot(timeout, hr_info, label=stats, marker='.')
                else:
                    ax.semilogx(timeout, hr_info, label=stats, marker='.', basex=10)

            ax.legend(loc='upper left', shadow=True)
            ax.grid(which='both')
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
    for stats_cat in {'mean', 'median', '95', '99', 'max'}:
        fig, ax = plt.subplots()
        fig.set_size_inches(20, 15)
        for cur_cat in categories.keys():
            x = [i[1] for i in categories[cur_cat][stats_cat]]
            y = [i[0] for i in categories[cur_cat][stats_cat]]
            ax.plot(x, y, label=cur_cat, marker='.')

        ax.legend(loc='upper left', shadow=True)
        ax.grid(which='both')
        plt.ylabel("Flow occupancy")
        plt.xlabel("Hit rate")
        plt.title("Summary")
        plt.savefig(dir_name + '/' + stats_cat +'_Summary')
        plt.close('all')






if __name__ == '__main__':
    # Get the user input
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('config_file', help="config file")
    arg_parser.add_argument('--linear', 
                    action="store_true", 
                    help="Time axis linear or log")
    args = arg_parser.parse_args()
    config_file = args.config_file
    linear = args.linear

    # Parse the config file
    config_instance = switch_parser.Config(config_file)
    config_instance.parse_config_file()
    config = config_instance.config
    
    # Initialize
    pathes = []
    file_cat = []
    times = []
    num_switches = 0

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
    parse_all(all_info, file_cat, times, linear=linear)
    print("Done. GL")
