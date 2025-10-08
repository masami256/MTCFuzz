#!/usr/bin/env python3

import argparse
import subprocess
import re
import tempfile
import yaml
import os
import shutil

def write_analyzed_data(cover_data, output_file):
    with open(output_file, "w") as f:
        f.write("Address,Function,File,Line,Count\n")
        for cd in cover_data:
            f.write(f"{cd['loaded_address']},{cd['function']},{cd['file']},{cd['line']},{cd['count']}\n")

    print(f"[+] Analyzed coverage data written to {output_file}")

def call_addr2line(addr2line, binary, addr_list):
    if not addr_list:
        return []

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
        for a in addr_list:
            tf.write(a + "\n")
        tf.flush()

        result = subprocess.run(
            [addr2line, "-e", binary, "-f", "-p", "-a", "@" + tf.name],
            capture_output=True,
            text=True,
            check=True
        )
    return result.stdout.strip().splitlines()

def run_addr2line(addresses, addr_count_map, config):
    results = []

    for target in config:
        if not "elf" in config[target]:
            continue

        target_addresses = []
        addr_pair = {}

        data = config[target]

        low = data["min_addr"]
        high = data["max_addr"]

        base_addr = data["base_addr"]

        for addr in addresses:
            addr = int(addr, 16)
            if addr >= low and addr <= high:
                actual_addr = hex(addr - base_addr)
                # print(f"{hex(addr)} - {hex(base_addr)} = {hex(addr - base_addr)}")
                target_addresses.append(actual_addr)
                addr_pair[actual_addr] = hex(addr)

        a2r_result = call_addr2line(config["addr2line"]["binary"], data["elf"], target_addresses)   
        for line in a2r_result:
            # e.g.:
            # 0x000000000000a704: tlb_range_check at /path/to/file.c:274
            match = re.match(r"^0x[0-9a-fA-F]+:\s+(.*?)\s+at\s+(.+):(\d+)(?:\s+\(discriminator\s+\d+\))?$", line)
            if match:
                func_name = match.group(1)
                file_path = match.group(2)
                line_num = int(match.group(3))
                address = int(line.split(":")[0].strip(), 16)
                addr = hex(address)
                if not addr in results:
                    d = {
                        "binary_offset_address": addr,
                        "loaded_address": addr_pair[addr],
                        "function": func_name,
                        "file": os.path.abspath(file_path),
                        "line": line_num,
                        "count": addr_count_map[addr_pair[addr]],
                    }
                    
                    results.append(d)

    return results

def parse_args():
    parser = argparse.ArgumentParser(description="Convert virtual addresses to offsets in a binary file.")
    parser.add_argument("--config", type=str, required=True, help="config yaml file path")
    parser.add_argument("--trace-log", type=str, required=True, help="qemu trace log file")
    parser.add_argument("--output", type=str, default="analyzed_coverage.csv", help="output file name")
    args = parser.parse_args()

    return args

def read_config(file_path):
    with open(file_path, "r") as f:
        data = yaml.safe_load(f)
    return data

def read_trace_log(trace_log):
    ret = {}
    with open(trace_log, "r") as f:
        for line in f:
            if not line.startswith("0x"):
                continue
            tmp = line.strip().split(",")
            addr_s = tmp[0].strip()
            count = int(tmp[1].strip())
            if addr_s:
                ret[addr_s] = count
    
    return ret

def main():
    args = parse_args()

    config = read_config(args.config)
    addr_count_map = read_trace_log(args.trace_log)

    addresses = sorted(addr_count_map.keys(), key=lambda x: int(x, 16))
    cover_data = run_addr2line(addresses, addr_count_map, config)

    write_analyzed_data(cover_data, args.output)

    shutil.copy(args.config, os.path.dirname(args.output))
if __name__ == "__main__":
    main()