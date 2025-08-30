#!/usr/bin/env python3

import sys
import pandas as pd
import numpy as np

def find_gap_threshold(addresses):
    diffs = np.diff(addresses)
    sorted_diffs = np.sort(diffs)

    hist, bin_edges = np.histogram(np.log1p(sorted_diffs), bins=100)
    min_bin_index = np.argmin(hist[len(hist)//4:len(hist)*3//4]) + len(hist)//4

    threshold = int(np.expm1(bin_edges[min_bin_index]))

    return threshold

def main(tracelog):
    with open(tracelog) as f:
        addresses = sorted(int(line, 16) for line in f)

    if len(addresses) < 2:
        print("Not enough addresses to group.")
        return

    max_gap = find_gap_threshold(addresses)
    print(f"# Inferred max gap: 0x{max_gap:x} ({max_gap} bytes)")

    ranges = []
    start = prev = addresses[0]
    for addr in addresses[1:]:
        if addr - prev <= max_gap:
            prev = addr
        else:
            ranges.append((start, prev))
            start = prev = addr
    ranges.append((start, prev))

    for start, end in ranges:
        print(f"0x{start:x} - 0x{end:x}")

if __name__ == "__main__":
    if not len(sys.argv) == 2:
        print(f"[*]Usage {sys.argv[0]} <trace log file>")
        exit(0)
    main(sys.argv[1])
