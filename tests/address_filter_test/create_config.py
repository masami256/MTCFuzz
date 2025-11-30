#!/usr/bin/env python3
import argparse
import json
import pprint

def parse_args():
    parser = argparse.ArgumentParser(description="Create address filter config")
    parser.add_argument("--input", required=True, help="Input JSON file with address data")
    parser.add_argument("--output", required=True, help="Output config file path")
    parser.add_argument("--max-filters", required=True, type=int, help="Maximum number of address filters to include")

    return parser.parse_args()

def main(args):
    config = None
    with open(args.input, "r") as f:
        config = json.load(f)
    
    count = len(config["address_filters"]["kernel"])
    print(f"[+] Original kernel address filters count: {count}")

    new_filter = []
    for i, addr_filter in enumerate(config["address_filters"]["kernel"]):
        # we have one filter for firmware address filter so we negate one from max_filters
        if i < args.max_filters - 1:
            new_filter.append(addr_filter)
        else:
            break
        
    config["address_filters"]["kernel"] = new_filter
    with open(args.output, "w") as f:
        json.dump(config, f, indent=4)

    print(f"[+] New address filters count: {args.max_filters}")
if __name__ == "__main__":
    main(parse_args())