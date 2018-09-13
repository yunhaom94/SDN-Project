"""
Timeout

1. Timeout is meaningless when under 10ms, thus only consider timeout beyond 10ms. Same for large timeout.
2. Reasonable range is from 10ms to 10s.
3. Since using log axis, should sample small timeouts intensively, but with sparse large timeouts:
    1. 10ms to 20ms; every 1ms
    2. 20ms to 40ms; every 2ms
    3. 40ms to 80ms; every 4ms
    4. 80ms to 160ms; every 8ms
    5. 160ms to 320ms; every 16ms
    6. 320ms to 640ms; every 32ms
    7. 640ms to 1280ms; every 64ms
    8. 1280ms to 2560ms; every 128ms
    9. 2560ms to 5120ms; every 256ms
    10. 5120ms to 102400ms; every 512ms

Rules


"""


import os
import argparse

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