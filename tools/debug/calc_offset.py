#!/usr/bin/env python3

import sys

if __name__ == "__main__":
    if not len(sys.argv) == 3:
        print(f"usage:{sys.argv[0]} <loaded address> <address in ELF file>")
        exit(1)
    
    la = int(sys.argv[1], 16)
    ea = int(sys.argv[2], 16)

    print(f"offset is {hex(la - ea)}")
