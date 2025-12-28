#!/usr/bin/env python3

import argparse
import json
import angr

import pprint

def parse_args():
    parser = argparse.ArgumentParser(description="Count basic blocks")
    parser.add_argument("--config", required=True, help="config json file")
    parser.add_argument("--binary", required=True, help="Path to binary file")
    parser.add_argument("--filter", required=True, help="kernel or firmware")
    parser.add_argument("--output", default="output.csv", help="Output filename")
    args = parser.parse_args()

    return args

def get_target_functions(config_file, filter_type):
    funcs = []

    with open(config_file) as f:
        j = json.load(f)
        filters = j["address_filters"][filter_type]
        for filter in filters:
            funcs.append(filter["name"])
    
    return funcs

def main(args):
    bbdata = {}

    funcs = get_target_functions(args.config, args.filter)

    print(f"Load {args.binary}")
    p = angr.Project(args.binary, load_options={'auto_load_libs': False})

    print("Create CFG")
    cfg = p.analyses.CFGFast()
    print("Create CFG Done.")
    
    for func in cfg.kb.functions.values():
        if func.name in funcs:
            bb_count = len(func.block_addrs)
            if func.name in bbdata:
                print(f"function {func.name} is already listed")
                continue
            bbdata[func.name] = bb_count
            
    bbdata = dict(sorted(bbdata.items(), key=lambda x: x[0]))
    with open(args.output, "w") as f:
        for name in bbdata:
            s = f"{name}, {bbdata[name]}\n"
            f.write(s)

if __name__ == "__main__":
    main(parse_args())