import pandas
pandas.set_option('precision', 3)
import csv
import os
import matplotlib.pyplot as plt
import numpy as np

linear = 1


# Construct a general header 
header = ["timeout", "multiplier", "max_packet", "99_packet", "95_packet",
              "mean_packet", "median_packet", "all_hr", "main_hr",
              "max_cache", "99_cache", "95_cache", "mean_cache", "median_cache"]
Q = {}
for i in range(len(header)):
    Q[header[i]] = i

# Construct plot instances
packet_cat = ["max_packet", "99_packet", "95_packet", "mean_packet", "median_packet"]
cache_cat = ["max_cache", "99_cache", "95_cache", "mean_cache", "median_cache"]

# Find all file_cat
file_cat = ["no_cache", "dynamic","fifo", "fixed_cache", "smart_time"]
file_cat = ["fixed_cache"]
file_out = {}

for category in file_cat:
    fp = pandas.read_csv(category + ".csv", sep=",")
    data = fp.values

    if (category != "fixed_cache"):
        file_out[category] = data
    else:
        # Handle different multiplier
        N, _ = data.shape
        multi = {}
        for i in range(N):
            cur_m = data[i, Q["multiplier"]]
            if cur_m in multi.keys():
                multi[cur_m].append(data[i, :])
            else:
                multi[cur_m] = [data[i, :]]
        for cur_m in multi.keys():
            new_catname = category + str(cur_m)
            file_out[new_catname] = np.array(multi[cur_m])
            





for cur_packet in packet_cat:
    fig, ax = plt.subplots()
    fig.set_size_inches(20, 15)
    for cur_cat in file_out.keys():
        data = file_out[cur_cat]
        hr = data[:, Q["all_hr"]]
        packet = data[:, Q[cur_packet]]

        if linear:
            ax.plot(hr, packet, label=cur_cat, marker='.')
        else:
            ax.semilogx(hr, packet, label=cur_cat, marker='.')

    ax.legend(loc='upper left', shadow=True)
    ax.grid(which='both')
    plt.ylabel("Flow occupancy")
    plt.xlabel("Hit rate")
    plt.title("Summary")
    plt.savefig(cur_packet + '_Summary')
    plt.close('all')

for cur_packet in cache_cat:
    fig, ax = plt.subplots()
    fig.set_size_inches(20, 15)
    for cur_cat in file_out.keys():
        data = file_out[cur_cat]
        hr = data[:, Q["all_hr"]]
        packet = data[:, Q[cur_packet]]

        if linear:
            ax.plot(hr, packet, label=cur_cat, marker='.')
        else:
            ax.semilogx(hr, packet, label=cur_cat, marker='.')

    ax.legend(loc='upper left', shadow=True)
    ax.grid(which='both')
    plt.ylabel("Flow occupancy")
    plt.xlabel("Hit rate")
    plt.title("Summary")
    plt.savefig(cur_packet + '_Summary')
    plt.close('all')


fig, ax = plt.subplots()
fig.set_size_inches(20, 15)
for cur_cat in file_out.keys():
    data = file_out[cur_cat]
    hr = data[:, Q["all_hr"]]

    cache = data[:, Q["mean_packet"]]
    packet = data[:, Q["mean_cache"]]
    ratio = cache / packet

    if linear:
        ax.plot(hr, ratio, label=cur_cat, marker='.')
    else:
        ax.semilogx(hr, packet, label=cur_cat, marker='.')

ax.legend(loc='upper left', shadow=True)
ax.grid(which='both')
plt.ylabel("ratio")
plt.xlabel("hr")
plt.title("Summary")
plt.savefig('_Summary')
plt.close('all')
        
