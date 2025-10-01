#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import glob
import pprint

def read_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)
    
def collect_trace_log_files(config):
    workdir = config["fuzzing"]["local_work_dir"]
    files = []

    glob_pattern = f"{workdir}/**/qemu_trace_log.log"
    for file in glob.glob(glob_pattern, recursive=True):
        files.append(file)
    
    return files

def parse_args():
    parser = argparse.ArgumentParser(description="Generate a report based on the provided arguments.")
    parser.add_argument("--config-json", type=str, required=True, help="config.json file path")
    parser.add_argument("--check-kernel-coverage", action="store_true", help="Check kernel coverage")
    parser.add_argument("--check-firmware-coverage", action="store_true", help="Check firmware coverage")
    parser.add_argument("--sort-by-count", action="store_true", help="Sort addresses by count")
    parser.add_argument("--sort-by-address", action="store_true", help="Sort addresses by address")
    parser.add_argument("--output", type=str, default="coverage_report.csv", help="Output file for the report")
    args = parser.parse_args()

    if not args.check_kernel_coverage and not args.check_firmware_coverage:
        parser.error("At least one of --check-kernel-coverage or --check-firmware-coverage must be specified.")

    if not args.sort_by_count and not args.sort_by_address:
        args.sort_by_address = True  # Default to sorting by address if no sort option is specified
    return args

def main():
    args = parse_args()
    config = read_json(args.config_json)

    trace_log_files = collect_trace_log_files(config)
    if len(trace_log_files) == 0:
        print("No trace log files found.")
        return
    
    filters = config["address_filters"]

    addresses = {}

    for trace_log in trace_log_files:
        with open(trace_log, "r") as f:
            for line in f:
                pc_found = False
                addr_s = line.strip()
                try:
                    addr = int(addr_s, 16)
                except Exception as e:
                    # print(f"trace_log: {trace_log} , addr_s: {addr_s}")
                    continue
                
                if args.check_kernel_coverage:
                    for kernel_range in filters["kernel"]:
                        lower = int(kernel_range["lower"], 16)
                        upper = int(kernel_range["upper"], 16)

                        if lower <= addr <= upper:
                            pc_found = True
                            if addr_s not in addresses:
                                addresses[addr_s] = 1
                            else:
                                addresses[addr_s] += 1
                            break
                        
                if not pc_found and args.check_firmware_coverage:
                    for firmware_range in filters["firmware"]:
                        lower = int(firmware_range["lower"], 16)
                        upper = int(firmware_range["upper"], 16)
                        if lower <= addr <= upper:
                            pc_found = True
                            if addr_s not in addresses:
                                addresses[addr_s] = 1
                            else:
                                addresses[addr_s] += 1
                            break

    address_items = list(addresses.items())
    if args.sort_by_count:
        address_items.sort(key=lambda x: x[1], reverse=True)
    elif args.sort_by_address:
        address_items.sort(key=lambda x: int(x[0], 16))

    with open(args.output, "w") as output_file:
        for addr, count in address_items:
            output_file.write(f"{addr},{count}\n")

if __name__ == "__main__":
    main()
    


