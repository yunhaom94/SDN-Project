'''
Parse the simulator switch's outputs
features:

'''
import argparse
import csv
import numpy as np


def parse(file_name):
    try:
        in_fp = open(file_name, "r", encoding="utf-8")
    except:
        print("Invalid file input")
        return

    # Create the result csv file:
    csv_name = file_name + "_parsed.csv"
    csv_fp = open(csv_name, "w+", newline='')
    header = ["time", "total_packets", "active_flows", "hit_rate"]
    writer = csv.DictWriter(csv_fp, delimiter=",", fieldnames=header)
    writer.writeheader()

    # Set parameters:
    time = 0
    interval = 0
    order = 0
    tracking_values = {"time": time}

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
            elif order == 8:
                tracking_values["hit_rate"] = value
                all_hit_rate.append(float(value))
            elif time == 0 and order == 3:
                # TODO: QUESTION
                interval = int(value) if int(value) < 100 else 100

        order += 1

        if line.strip() == "*":
            time += interval
            order = 0
            writer.writerow(tracking_values)
            tracking_values = {"time":time}

    csv_fp.close()





if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('input', help="raw outputs from simulator")

    args = arg_parser.parse_args()
    input_file = args.input

    print("Parsing " + input_file)
    parse(input_file)
    print("Done")
