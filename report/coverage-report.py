#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import glob
import os
from bisect import bisect_right

def read_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)
    
def collect_trace_log_files(test_result_dir):
    files = []

    glob_pattern = f"{test_result_dir}/**/qemu_trace_log.log"
    for file in glob.glob(glob_pattern, recursive=True):
        files.append(file)
    
    return files

def parse_args():
    parser = argparse.ArgumentParser(description="Generate a report based on the provided arguments.")
    parser.add_argument("--config-json", type=str, required=True, help="config.json file path")
    parser.add_argument("--test-result-dir", required=True, help="Test result dir")
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

def create_merged_filter(check_kernel_coverage, check_firmware_coverage, address_filters):
    result = []
    
    if check_kernel_coverage:
        for data in address_filters["kernel"]:
            lower = int(data["lower"], 16)
            upper = int(data["upper"], 16)
            result.append([lower, upper])
    
    if check_firmware_coverage:
        for data in address_filters["firmware"]:
            lower = int(data["lower"], 16)
            upper = int(data["upper"], 16)
            result.append([lower, upper])

    result.sort(key=lambda x: x[0])
    return result

def main():
    args = parse_args()
    config = read_json(args.config_json)

    test_result_dir = os.path.abspath(args.test_result_dir)
    trace_log_files = collect_trace_log_files(test_result_dir)
    if len(trace_log_files) == 0:
        print("No trace log files found.")
        return
    
    addresses = {}

    filters = create_merged_filter(args.check_kernel_coverage, args.check_firmware_coverage, config["address_filters"])

    starts = [pair[0] for pair in filters]

    def addr_in_filters(addr, filters, starts):
        idx = bisect_right(starts, addr) - 1
        if idx < 0:
            return False
        lower, upper = filters[idx]
        return lower <= addr <= upper


    for trace_log in trace_log_files:
        with open(trace_log, "r") as f:
            for line in f:
                addr_s = line.strip()

                if addr_s in addresses:
                    addresses[addr_s] += 1
                    continue

                try:
                    addr = int(addr_s, 16)
                except Exception:
                    continue

                if addr_in_filters(addr, filters, starts):
                    addresses[addr_s] = 1

    address_items =list(addresses.items())
    if args.sort_by_count:
        address_items.sort(key=lambda x: x[1], reverse=True)
    elif args.sort_by_address:
        address_items.sort(key=lambda x: int(x[0], 16))

    with open(args.output, "w") as output_file:
        for addr, count in address_items:
            output_file.write(f"{addr},{count}\n")
        print(f"[+]Coverage report written to {args.output}")

if __name__ == "__main__":
    main()
    


