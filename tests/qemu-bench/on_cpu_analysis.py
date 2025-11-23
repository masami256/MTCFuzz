#!/usr/bin/env python3
import sys
import csv
import argparse

def parse_bpftrace_map(path):
    """
    Parse a bpftrace map dump like:

      @[
              frame1
              frame2
              ...
      ]: 3

    and return a dict: { "frame1;frame2;...": count }
    """
    stacks = {}
    with open(path, "r") as f:
        in_block = False
        frames = []

        for raw in f:
            line = raw.rstrip("\n")

            if not in_block:
                # Start of a new stack block: "@["
                if line.startswith("@["):
                    in_block = True
                    frames = []
                else:
                    continue
            else:
                # End of block: "]: N"
                if line.startswith("]:"):
                    # Parse count
                    try:
                        count = int(line.split(":", 1)[1].strip())
                    except Exception:
                        count = 1

                    clean_frames = [fr.strip() for fr in frames if fr.strip()]
                    key = ";".join(clean_frames)

                    stacks[key] = stacks.get(key, 0) + count
                    in_block = False
                else:
                    frames.append(line)

    return stacks


def main():
    parser = argparse.ArgumentParser(
        description="Analyze bpftrace on-CPU map output and produce a CSV."
    )
    parser.add_argument("--input", "-i", default="on_cpu_log.txt",
                        help="Input bpftrace log file (default: on_cpu_log.txt)")
    parser.add_argument("--output", "-o", default="on_cpu_analysis.csv",
                        help="Output CSV file (default: on_cpu_analysis.csv)")

    args = parser.parse_args()

    print(f"[+] Reading   : {args.input}")
    stacks = parse_bpftrace_map(args.input)

    print(f"[+] Writing   : {args.output}")
    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["count", "stack"])

        # Sort by count descending
        for stack, cnt in sorted(stacks.items(), key=lambda x: -x[1]):
            writer.writerow([cnt, stack])

    print("[+] Done.")


if __name__ == "__main__":
    main()
