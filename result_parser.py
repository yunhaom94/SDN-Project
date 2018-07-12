'''
Parse the simulator switch output to an .csv so that it would be easy to create a graph
'''
import argparse
import csv
import numpy as np


def parse(file_name):
    csvfile_name = file_name + "_parsed.csv"
    csvfile = open(csvfile_name, "w+", newline='')
    headers = ["Time", "Active_Flows", "Hit_Rate"]
    writer = csv.DictWriter(csvfile, delimiter=",", fieldnames=headers)
    writer.writeheader()

    time = 0
    interval = 0
    order = 0 # the numbers are in order, i.e third one after * is active flows
    tracking_values = {"Time":time}

    all_active_flows = []
    all_hit_rate = []

    with open(file_name, "r", encoding="utf-8") as f:
        line = f.readline()
        while line:
            content = line.split(":")

            if len(content) == 2:
                value = content[1].strip()
                if order == 4:
                    tracking_values["Active_Flows"] = value
                    all_active_flows.append(float(value))
                elif order == 8:
                    tracking_values["Hit_Rate"] = value
                    all_hit_rate.append(float(value))
                elif time == 0 and order == 3:
                    interval = int(value) if int(value) < 100 else 100
                
            order += 1

            if line.strip() == "*":
                time += interval
                order = 0
                writer.writerow(tracking_values)
                tracking_values = {"Time":time}

            line = f.readline()

    

    ohter_stats = '''
    
Active Flows Stats: 
Mean: {af_mean}
Medium: {af_med}
99th percentile: {af_99}
95th percentile: {af_95}

    '''.format(
        af_mean=np.mean(all_active_flows),
        af_med=np.median(all_active_flows),
        af_99=np.percentile(all_active_flows, 99),
        af_95=np.percentile(all_active_flows, 95)
    )

    csvfile.write(ohter_stats)

    csvfile.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("result_file", help="Path to config file")

    args = parser.parse_args()
    result_file = args.result_file
    print("Parsing " + result_file)
    parse(result_file)
    print("Done")

