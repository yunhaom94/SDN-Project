'''
Parse the simulator switch output to an excel sheet(.xlsx) so that it would be easy to create a graph
'''
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("result_file", help="Path to config file")

    args = parser.parse_args()
    result_file = args.result_file

    with open(result_file, "r", encoding="utf-8") as f:
        line = f.readline()
        while line:
            content = line.split(":")
            if len(content) == 2:
                value = content[1].strip()
                print(value)

            if line.strip() == "*":
                print(line)

            line = f.readline()