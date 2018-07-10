'''
Parse the simulator switch output to an .csv so that it would be easy to create a graph
'''
import argparse
import csv



def parse(file_name):
    csvfile_name = file_name + "_parsed.csv"
    csvfile = open(csvfile_name, "w+", newline='')
    headers = ["Time", "Active_Flows", "Hit_Rate"]
    writer = csv.DictWriter(csvfile, delimiter=",", fieldnames=headers)
    writer.writeheader()

    time = 0
    order = 0 # the numbers are in order, i.e third one after * is active flows
    tracking_values = {"Time":time}
    with open(file_name, "r", encoding="utf-8") as f:
        line = f.readline()
        while line:
            content = line.split(":")
            if len(content) == 2:
                value = content[1].strip()
                if order == 3:
                    tracking_values["Active_Flows"] = value
                elif order == 6:
                    tracking_values["Hit_Rate"] = value
                
                order += 1

            if line.strip() == "*":
                time += 100 # because we have a dump time of 100
                order = 0
                writer.writerow(tracking_values)
                tracking_values = {"Time":time}

            line = f.readline()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("result_file", help="Path to config file")

    args = parser.parse_args()
    result_file = args.result_file
    print("Parsing " + result_file)
    parse(result_file)
    print("Done")

