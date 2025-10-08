#!/usr/bin/env python3

import argparse

def is_power_of_two(x):
    return x > 0 and (x & (x - 1)) == 0

def parse_args():
    parser = argparse.ArgumentParser(description="Calulate TA address range")
    parser.add_argument("--loaded-address", required=True, help="loaded address")
    parser.add_argument("--size", required=True, help="size of the TA(decimal)")
    parser.add_argument("--align", default="0x1000", help="align size(hex) to page size (default 0x1000 bytes)")
    args = parser.parse_args()

    return args

def main():
    args = parse_args()

    ta_address = int(args.loaded_address, 16)
    orig_size = int(args.size)
    align = int(args.align, 16)
    if not is_power_of_two(align):
        print("Align size must be a power of two")
        exit(1)
    
    aligned_size = (orig_size + align - 1) & ~(align - 1)

    print(f"Address range is {hex(ta_address)} - {hex(ta_address + aligned_size)}")

if __name__ == "__main__":
    main()


