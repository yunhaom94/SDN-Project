import argparse
import pandas
import csv
import os
import numpy as np

def simplify(fp):
    data = fp.values
    print(data.shape)

if __name__ == '__main__':
    header = ["timeout", "multiplier", "max_packet", "99_packet", "95_packet",
              "mean_packet", "median_packet", "all_hr", "main_hr",
              "max_cache", "99_cache", "95_cache", "mean_cache", "median_cache"]

    # Generate timeout list
    timeout_list = []
    start = 10
    for i in range(6):
        cur_range = []
        for j in range(10):
            cur_range.append(start)
            start = start + 10 * (2 ** i)
        timeout_list.append(cur_range)

    # Generate Multiplier
    mult_list = []
    gap_list = [10, 4, 2, 1, 0.3, 0.1]
    for i in range(6):
        start = 1
        cur_range = []
        for j in range(10):
            cur_range.append(start)
            start = start + gap_list[i]
        mult_list.append(cur_range)

    if 0:
        # Generate no cache csv:
        csv_name = "no_cache.csv"
        csv_fp = open(csv_name, "w+", newline='')
        writer = csv.DictWriter(csv_fp, delimiter=',', fieldnames=header)
        writer.writeheader()
        for i in range(6):
            for j in range(10):
                cur_id = i * 10 + j
                cur_timeout = timeout_list[i][j]
                filename = "log_SW" + str(cur_id) + ".csv"
                try:
                    fp = pandas.read_csv(filename, sep=",")
                except:
                    continue
                
                data = fp.values
                # TODO: OMIT FIRST 10%
                N, _ = data.shape
                data = data[int(N*0.1):, :]

                active_flows = data[:, 2]
                hit_rate = data[-1, 3]

                tracking_values = {}
                tracking_values["timeout"] = cur_timeout

                tracking_values["max_packet"] = np.max(active_flows)
                tracking_values["99_packet"] = np.percentile(active_flows, 99)
                tracking_values["95_packet"] = np.percentile(active_flows, 95)
                tracking_values["mean_packet"] = np.mean(active_flows)
                tracking_values["median_packet"] = np.median(active_flows)

                tracking_values["all_hr"] = hit_rate
                writer.writerow(tracking_values)
        csv_fp.close()

        # Generate fixed timeout test files
        cur_id = 60
        csv_name = "fixed_cache.csv"
        csv_fp = open(csv_name, "w+", newline='')
        writer = csv.DictWriter(csv_fp, delimiter=',', fieldnames=header)
        writer.writeheader()
        for i in range(6):
            for j in range(10):
                for k in range(10):
                    cur_timeout = timeout_list[i][j]
                    multi = mult_list[i][k]

                    filename = "log_SW" + str(cur_id) + ".csv"
                    try:
                        fp = pandas.read_csv(filename, sep=",")
                    except:
                        continue

                    data = fp.values
                    # TODO: OMIT FIRST 10%
                    N, _ = data.shape
                    data = data[int(N*0.1):, :]
                    
                    active_flows = data[:, 2]
                    hit_rate = data[-1, 3]
                    total_packet = data[-1, 1]
                    cache_hr = data[-1, -1]
                    cache_size = data[:, -2]
                    
                    # Calculate main table hit rate
                    c1 = cache_hr * 1.0
                    c2 = total_packet * 1.0
                    c3 = hit_rate * total_packet * 1.0
                    main_hr = c1 * (c2 - c3)
                    main_hr = main_hr / (c1 - 1) + c3
                    main_hr = main_hr / c2

                    tracking_values = {}
                    tracking_values["timeout"] = cur_timeout
                    tracking_values["multiplier"] = multi

                    tracking_values["max_packet"] = np.max(active_flows)
                    tracking_values["99_packet"] = np.percentile(active_flows, 99)
                    tracking_values["95_packet"] = np.percentile(active_flows, 95)
                    tracking_values["mean_packet"] = np.mean(active_flows)
                    tracking_values["median_packet"] = np.median(active_flows)

                    tracking_values["all_hr"] = hit_rate
                    tracking_values["main_hr"] = main_hr

                    tracking_values["max_cache"] = np.max(cache_size)
                    tracking_values["99_cache"] = np.percentile(cache_size, 99)
                    tracking_values["95_cache"] = np.percentile(cache_size, 95)
                    tracking_values["mean_cache"] = np.mean(cache_size)
                    tracking_values["median_cache"] = np.median(cache_size)

                    writer.writerow(tracking_values)
                    cur_id += 1
        csv_fp.close()

        # Generate smart time test files
        cur_id = 720
        csv_name = "smart_time.csv"
        csv_fp = open(csv_name, "w+", newline='')
        writer = csv.DictWriter(csv_fp, delimiter=',', fieldnames=header)
        writer.writeheader()
        for i in range(6):
            for j in range(10):
                cur_timeout = timeout_list[i][j]
                filename = "log_SW" + str(cur_id) + ".csv"
                try:
                    fp = pandas.read_csv(filename, sep=",")
                except:
                    cur_id += 1
                    continue

                data = fp.values
                # TODO: OMIT FIRST 10%
                N, _ = data.shape
                data = data[int(N*0.1):, :]
                
                active_flows = data[:, 2]
                hit_rate = data[-1, 3]

                tracking_values = {}
                tracking_values["timeout"] = cur_timeout

                tracking_values["max_packet"] = np.max(active_flows)
                tracking_values["99_packet"] = np.percentile(active_flows, 99)
                tracking_values["95_packet"] = np.percentile(active_flows, 95)
                tracking_values["mean_packet"] = np.mean(active_flows)
                tracking_values["median_packet"] = np.median(active_flows)

                tracking_values["all_hr"] = hit_rate

                writer.writerow(tracking_values)
                cur_id += 1
        csv_fp.close()
    
    # Generate dynamic timeout test files
    cur_id = 660
    csv_name = "dynamic.csv"
    csv_fp = open(csv_name, "w+", newline='')
    writer = csv.DictWriter(csv_fp, delimiter=',', fieldnames=header)
    writer.writeheader()
       
    for i in range(6):
        for j in range(10):
            cur_timeout = timeout_list[i][j]
            filename = "log_SW" + str(cur_id) + ".csv"
            try:
                fp = pandas.read_csv(filename, sep=",")
            except:
                cur_id += 1
                continue

            data = fp.values
            # TODO: OMIT FIRST 10%
            N, _ = data.shape
            data = data[int(N*0.1):, :]
            
            active_flows = data[:, 2]
            hit_rate = data[-1, 3]
            total_packet = data[-1, 1]
            cache_hr = data[-1, -1]
            cache_size = data[:, -2]
            
            # Calculate main table hit rate
            c1 = cache_hr * 1.0
            c2 = total_packet * 1.0
            c3 = hit_rate * total_packet * 1.0
            main_hr = c1 * (c2 - c3)
            main_hr = main_hr / (c1 - 1) + c3
            main_hr = main_hr / c2

            tracking_values = {}
            tracking_values["timeout"] = cur_timeout

            tracking_values["max_packet"] = np.max(active_flows)
            tracking_values["99_packet"] = np.percentile(active_flows, 99)
            tracking_values["95_packet"] = np.percentile(active_flows, 95)
            tracking_values["mean_packet"] = np.mean(active_flows)
            tracking_values["median_packet"] = np.median(active_flows)

            tracking_values["all_hr"] = hit_rate
            tracking_values["main_hr"] = main_hr

            tracking_values["max_cache"] = np.max(cache_size)
            tracking_values["99_cache"] = np.percentile(cache_size, 99)
            tracking_values["95_cache"] = np.percentile(cache_size, 95)
            tracking_values["mean_cache"] = np.mean(cache_size)
            tracking_values["median_cache"] = np.median(cache_size)

            writer.writerow(tracking_values)
            cur_id += 1
    
