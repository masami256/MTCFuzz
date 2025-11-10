#!/usr/bin/env python3
import re
import subprocess
import argparse
import json
import sys
import pprint

FUNC_LINE_RE = re.compile(r'^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$')

def run_objdump(objdump: str, binary: str) -> str:
    """Run objdump and return stdout as text."""
    cmd = [objdump, "-t", "-C", binary]
    res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout

def parse_objdump_text(text: str):
    """Yield (address, symbol) from objdump -t output."""
    functions = []
    pattern = re.compile(r"^([0-9a-fA-F]+)\s+\S+\s+F\s+\S+\s+([0-9a-fA-F]+)\s+(\S+)$")

    for line in text.splitlines():
        match = pattern.match(line.strip())
        if match:
            addr_hex, size_hex, name = match.groups()
            size = int(size_hex, 16)
            functions.append({
                "name": name,
                "address": hex(int(addr_hex, 16)),
                "size": size
            })

    return functions

def create_address_filter_list(address_data: dict) -> list:
    """Create address filter list from address data."""
    address_list = []

    for name in address_data:
        d = address_data[name]
        pair = {
            "name": name,
            "lower": d["start"], 
            "upper": d["end"],
        }
        address_list.append(pair)

    return address_list

def read_target_list(filepath: str):
    """Read target list from a file, return list of file paths."""
    targets = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.endswith(".c"):
                if line and not line.startswith("#"):
                    targets.append(line.replace(".c", ".o"))
            elif line.endswith(".o"):
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets

def merge_address_list(config_path: str, address_list: list, target: str,replace: bool) -> dict:
    """Merge address list into config file."""
    if not config_path:
        return

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    if "address_filters" not in config:
        config["address_filters"] = {}

    if target not in config["address_filters"]:
        config["address_filters"][target] = []

    if replace:
        config["address_filters"][target] = address_list
    else:
        config["address_filters"][target].extend(address_list)

    return config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract function headers from objdump output as CSV: address,name")
    base_group = parser.add_argument_group("Address filter options")
    filter_group = parser.add_argument_group("Config file options")

    base_group.add_argument("--target-list", required=True, help="Target .c file names(this file name convert to .o file) or .o file names list")
    base_group.add_argument("--objdump", required=True, help="Path to objdump binary")
    base_group.add_argument("--binary", required=True, help="Binary file to analyze. for example: vmlinux")
    base_group.add_argument("--base-address", help="Base address to adjust function addresses", type=str, default="0x0")
    base_group.add_argument("--output", help="Output file path (default: stdout)")

    filter_group.add_argument("--config", help="Config file to merge address filters", type=str)
    filter_group.add_argument("--replace", action="store_true", help="Replace address filters in config file", default=False)
    filter_group.add_argument("--filter-target", help="Target name in address filter in the config(kernel, firmware)", type=str, required=True)

    return parser.parse_args()


def main():
    
    args = parse_args()
    target_files = read_target_list(args.target_list)

    target_functions = {}
    for target in target_files:
        text = run_objdump(args.objdump, target)
        rows = list(parse_objdump_text(text))
        for row in rows:
            name = row["name"]
            target_functions[name] = row
            
    binry_analysis_result = run_objdump(args.objdump, args.binary)
    all_functions = {}
    rows = list(parse_objdump_text(binry_analysis_result))
    for row in rows:
        name = row["name"]
        all_functions[name] = row

    address_data = {}

    base_address = int(args.base_address, 16)

    for name in all_functions:
        if name in target_functions:
            addr = hex(int(all_functions[name]["address"], 16) + base_address)
            size = all_functions[name]["size"]
            address_data[name] = {"start": addr, "end": hex(int(addr, 16) + size)}

    address_list = create_address_filter_list(address_data)

    config = merge_address_list(args.config, address_list, args.filter_target, args.replace)

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    else:
        json.dump(config, sys.stdout, indent=4)

if __name__ == "__main__":
    main()
