#! /usr/bin/env python3
import os
from pathlib import Path
import argparse
import json
from bisect import bisect_right

QEMU_TRACE_LOG_FILE = "qemu_trace_log.log"

def write_csv(output_filename, coverages):
    t = 0
    with open(output_filename, "w") as f:
        for test_no in coverages:
            d = coverages[test_no]
            t += d['new_count']
            f.write(f"{d['test_no']},{d['new_count']},{t}\n")


def apply_filter(trace_logs, filters, coverages, test_no):
    starts = [pair[0] for pair in filters]

    def addr_in_filters(addr, filters, starts):
        idx = bisect_right(starts, addr) - 1
        if idx < 0:
            return False
        lower, upper = filters[idx]
        return lower <= addr <= upper

    new_count = 0
    for line in trace_logs:
        addr_s = line.strip()
        try:
            addr = int(addr_s, 16)
        except Exception:
            continue

        if (not addr in coverages) and (not addr_in_filters(addr, filters, starts)):
            continue

        new_count += 1
    coverages[test_no] = {
        "test_no": test_no,
        "new_count": new_count,
    }
    

def read_qemu_trace_log(filename):
    with open(filename) as f:
       return f.readlines()


def create_merged_filter(config):
    result = []
    
    address_filters = config["address_filters"]
    for data in address_filters["kernel"]:
        lower = int(data["lower"], 16)
        upper = int(data["upper"], 16)
        result.append([lower, upper])
    
    for data in address_filters["firmware"]:
        lower = int(data["lower"], 16)
        upper = int(data["upper"], 16)
        result.append([lower, upper])

    result.sort(key=lambda x: x[0])
    return result


def read_config(config_path):
    with open(config_path) as f:
        return json.load(f)


def main(args):
    coverages = {}

    config = read_config(args.config)

    filters = create_merged_filter(config)
    base_dir = Path(os.path.abspath(args.result_dir))
    files = sorted(base_dir.rglob(QEMU_TRACE_LOG_FILE))

    for test_no, file in enumerate(files):
        print(f"[+]Processing {file}")
        trace_logs = read_qemu_trace_log(file)
        apply_filter(trace_logs, filters, coverages, test_no)
    
    write_csv(args.output, coverages)


def parse_args():
    parser = argparse.ArgumentParser(description="Coverage Accumlator")
    parser.add_argument("--config", required=True, help="config json file")
    parser.add_argument("--result-dir", required=True, help="Path to test result directory")
    parser.add_argument("--output", required=True, help="Output file name")
    args = parser.parse_args()

    return args

if __name__ == "__main__":
    main(parse_args())