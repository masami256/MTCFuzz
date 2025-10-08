#!/usr/bin/env python3

import argparse
import subprocess
import re
import tempfile
import yaml

def write_analyzed_data(cover_data, output_file):
    with open(output_file, "w") as f:
        f.write("Address in ELF,Loaded address,Function,File,Line,Count\n")
        for cd in cover_data:
            f.write(f"{cd["binaly_offset_address"]},{cd["loaded_address"]},{cd["function"]},{cd["file"]},{cd["line"]}\n")

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
    
def run_addr2line(addresses, config):
    config = read_config(config)
    addr2line = config["addr2line"]["binary"]

    results = []

    for target in config:
        if not "elf" in config[target]:
            continue

        data = config[target]
        low = data["min_addr"]
        high = data["max_addr"]

        target_addresses = []

        addr_pair = {}

        base_addr = data["base_addr"]
        for addr in addresses:
            if addr >= low and addr <= high:
                actual_addr = hex(addr - base_addr)
                # print(f"{hex(addr)} - {hex(base_addr)} = {hex(addr - base_addr)}")
                target_addresses.append(actual_addr)
                addr_pair[actual_addr] = hex(addr)

        a2r_result = call_addr2line(addr2line, data["elf"], target_addresses)

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
                results.append({
                    "binaly_offset_address": addr,
                    "loaded_address": addr_pair[addr],
                    "function": func_name,
                    "file": file_path,
                    "line": line_num
                })

    return results

def read_config(filepath):
    with open(filepath) as f:
        return yaml.safe_load(f)
    
def read_trace_log(trace_log):
    with open(trace_log) as f:
        lines = f.readlines()

    if lines and not lines[0].strip().startswith("0x"):
        lines = lines[1:]

    return sorted(set(int(line.strip(), 16) for line in lines if line.strip()))

def parse_args():
    parser = argparse.ArgumentParser(description="Convert virtual addresses to offsets in a binary file.")
    parser.add_argument("--config", required=True, help="yaml config file")
    parser.add_argument("--trace-log", required=True, help="qemu trace log file")
    parser.add_argument("--output", default="analyzed_coverage.csv", help="output file name")
    parser.add_argument("--addr2line",default="riscv64-linux-gnu-addr2line", help="path to addr2line binary")
    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    addresses = read_trace_log(args.trace_log)

    cover_data = run_addr2line(addresses, args.config)

    write_analyzed_data(cover_data, args.output)

if __name__ == "__main__":
    main()