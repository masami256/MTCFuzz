#!/usr/bin/env python3

import argparse
import subprocess
import re
import tempfile

def write_analyzed_data(cover_data, output_file):
    with open(output_file, "w") as f:
        f.write("Address,Function,File,Line,Count\n")
        for cd in cover_data:
            f.write(f"{cd['address']},{cd['function']},{cd['file']},{cd['line']}\n")

    print(f"[+] Analyzed coverage data written to {output_file}")

def call_addr2line(addr2line, binary, addr_list):
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
    
def run_addr2line(addresses, args):
    results = {}

    low = int(args.min_address, 16)
    high = int(args.max_address, 16)

    target_addresses = []

    for addr in addresses:
        if addr >= low and addr <= high:
            actual_addr = hex(addr - int(args.base_addr, 16))
            # print(f"{hex(addr)} - {args.base_addr} = {hex(addr - int(args.base_addr, 16))}")
            target_addresses.append(actual_addr)

    a2r_result = call_addr2line(args.addr2line, args.binary, target_addresses)

    results = []

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
                "address": addr,
                "function": func_name,
                "file": file_path,
                "line": line_num
            })

    return results

def read_trace_log(trace_log):
    with open(trace_log) as f:
        return sorted(set(int(line.strip(), 16) for line in f if line.strip()))

def parse_args():
    parser = argparse.ArgumentParser(description="Convert virtual addresses to offsets in a binary file.")
    parser.add_argument("--base-addr", default="0x0", help="base address")
    parser.add_argument("--min-address", default="0x0", help="lowest address to check")
    parser.add_argument("--max-address", default="0xffffffffffffffff")
    parser.add_argument("--trace-log", required=True, help="qemu trace log file")
    parser.add_argument("--output", default="analyzed_coverage.csv", help="output file name")
    parser.add_argument("--addr2line",default="riscv64-linux-gnu-addr2line", help="path to addr2line binary")
    parser.add_argument("--binary", required=True, help="Target binary")
    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    addresses = read_trace_log(args.trace_log)

    cover_data = run_addr2line(addresses, args)

    write_analyzed_data(cover_data, args.output)

if __name__ == "__main__":
    main()