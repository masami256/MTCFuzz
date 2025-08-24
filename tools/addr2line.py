#!/usr/bin/env python3

import argparse
import subprocess
import re
import tempfile

def write_analyzed_data(addresses, cover_data, trace_log, output_file):
    with open(output_file, "w") as f:
        f.write("Address,Function,File,Line,Count\n")
        for addr in addresses:
            if not (addr in trace_log and addr in cover_data):
                continue
            td = trace_log[addr]
            cd = cover_data[addr]

            f.write(f"{cd['address']},{cd['function']},{cd['file']},{cd['line']},{td}\n")

    print(f"[+] Analyzed coverage data written to {output_file}")

def run_addr2line(addresses, config, base_addr, addr2line):
    results = {}

    kernel_binary = config["fuzzing"]["kernel_binary"]
    firmware_binary = config["fuzzing"]["firmware_binary"]

    filters = config["address_filters"]

    kernel_addrs = []
    firmware_addrs = []
    addr_map = {}  # maps processed addr -> original addr

    for addr in addresses:
        addr_i = int(addr, 16)
        pc_found = False

        for kernel_range in filters["kernel"]:
            lower = int(kernel_range["lower"], 16)
            upper = int(kernel_range["upper"], 16)

            if lower <= addr_i <= upper:
                kernel_addrs.append(addr)
                addr_map[addr_i] = addr
                pc_found = True
                break

        if not pc_found:
            for firmware_range in filters["firmware"]:
                lower = int(firmware_range["lower"], 16)
                upper = int(firmware_range["upper"], 16)

                if lower <= addr_i <= upper:
                    actual_addr = hex(addr_i - int(base_addr, 16))
                    firmware_addrs.append(actual_addr)
                    addr_map[int(actual_addr, 16)] = addr
                    pc_found = True
                    break

        if not pc_found:
            continue

    def call_addr2line(binary, addr_list):
        if not addr_list:
            return []
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
            for a in addr_list:
                tf.write(a + '\n')
            tf.flush()

            result = subprocess.run(
                [addr2line, "-e", binary, "-f", "-p", "-a", "@" + tf.name],
                capture_output=True,
                text=True,
                check=True
            )
        return result.stdout.strip().splitlines()

    kernel_lines = call_addr2line(kernel_binary, kernel_addrs)
    firmware_lines = call_addr2line(firmware_binary, firmware_addrs)

    for line in kernel_lines + firmware_lines:
        # e.g.:
        # 0x000000000000a704: tlb_range_check at /path/to/file.c:274
        match = re.match(r"^0x[0-9a-fA-F]+:\s+(.*?)\s+at\s+(.+):(\d+)(?:\s+\(discriminator\s+\d+\))?$", line)
        if match:
            func_name = match.group(1)
            file_path = match.group(2)
            line_num = int(match.group(3))
            address = int(line.split(":")[0].strip(), 16)
            orig_addr = addr_map.get(address)
            if orig_addr:
                addr = hex(address)
                results[orig_addr] = {
                    "address": addr,
                    "function": func_name,
                    "file": file_path,
                    "line": line_num
                }

    return results

def parse_args():
    parser = argparse.ArgumentParser(description="Convert virtual addresses to offsets in a binary file.")
    parser.add_argument("--base-addr", type=str, required=True, help="base address")
    parser.add_argument("--config-json", type=str, required=True, help="config.json file path")
    parser.add_argument("--trace-log", type=str, required=True, help="qemu trace log file")
    parser.add_argument("--output", type=str, default="analyzed_coverage.csv", help="output file name")
    parser.add_argument("--addr2line", type=str, default="riscv64-linux-gnu-addr2line", help="path to addr2line binary")
    args = parser.parse_args()

    return args

def read_json(file_path):
    import json
    with open(file_path, "r") as f:
        data = json.load(f)
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

    config = read_json(args.config_json)
    trace_log = read_trace_log(args.trace_log)

    addresses = sorted(trace_log.keys(), key=lambda x: int(x, 16))
    cover_data = run_addr2line(addresses, config, args.base_addr, args.addr2line)

    write_analyzed_data(addresses, cover_data, trace_log, args.output)

if __name__ == "__main__":
    main()