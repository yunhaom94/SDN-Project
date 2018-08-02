'''
Parse the simulator switch's outputs
features:

'''
import argparse
import csv
import numpy as np
import matplotlib.pyplot as plt
import os

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


def parse(file_name):
    try:
        in_fp = open(file_name, "r", encoding="utf-8")
    except:
        print("Invalid file input")
        return

    # Create a directory to contain plots and information
    dir_name = file_name + '_dir'
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
    order = 0
    tracking_values = {}
    tracking_values["time"] = time

    all_time = []
    all_packets = []
    all_active_flows = []
    all_hit_rate = []

    for line in in_fp:
        content = line.split(":")

        if len(content) == 2:
            value = content[1].strip()
            if order == 2:
                tracking_values["total_packets"] = value
                all_packets.append(float(value))
            if order == 4:
                tracking_values["active_flows"] = value
                all_active_flows.append(float(value))
            elif order == 7:
                tracking_values["hit_rate"] = value
                all_hit_rate.append(float(value))
            elif time == 0 and order == 3:
                interval = int(value) if int(value) < 100 else 100

        order += 1

        if line.strip() == "*":
            time += interval
            all_time.append(time)
            order = 0
            writer.writerow(tracking_values)
            tracking_values["time"] = time

    plot(all_time, all_active_flows, "Hit Rate")
    plt.savefig(dir_name + '/' + 'flow')
    plot(all_time, all_hit_rate, "Hit Rate", linestyle='-')
    plt.savefig(dir_name + '/' + 'hit_rate')

    csv_fp.close()





if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('input', help="raw outputs from simulator")

    args = arg_parser.parse_args()
    input_file = args.input

    print("Parsing " + input_file)
    parse(input_file)
    print("Done")
