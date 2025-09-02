#!/usr/bin/env python3

import argparse
import pprint

def read_crash_trace(file):
        return [line.strip() for line in open(file) if not line.startswith("Address")]

def read_addr2line_results(filepath):
    tmp = []

    with open(filepath) as f:
        tmp.extend(line.strip() for line in f if not line.startswith("Address"))
    
    ret = {}
    for line in tmp:

        cols = line.split(",")
        addr = cols[0].strip()

        if not addr in ret:
            ret[addr] = {
                "addr": addr,
                "func": cols[2].strip(),
                "path": cols[3].strip(),
                "line": cols[4].strip(),
            }
            
    return ret

def main(args):
    
    src_info = read_addr2line_results(args.addr2line_result)
    traces = read_crash_trace(args.crash_trace)

    result = []
    for trace in traces:
        if trace in src_info:
             d = src_info[trace]
             result.append(f"{d["addr"]}: {d["func"]} {d["path"]} {d["line"]}\n")
        
    with open(args.output, "w") as f:
         for line in result:
            f.write(line)

    print(f"[+]File output to {args.output}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create all trace file from coverage data")
    parser.add_argument("--crash-trace", required=True, help="crash trace file")
    parser.add_argument("--output", default="all_trace.txt", help="output all trace file")
    parser.add_argument("--addr2line-result", required=True, help="addr2line analyzed files")

    args = parser.parse_args()
    main(args)
