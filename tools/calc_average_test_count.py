#!/usr/bin/env python3
import argparse
import glob
import re
import os
import pprint


UNIT_TO_SECONDS = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 60 * 60 * 24,
}

def parse_duration(s: str) -> int:
    """
    Convert duration string like '5m', '1h', '30s', '2d' to seconds.
    """
    m = re.fullmatch(r"(\d+)([smhd])", s)
    if not m:
        raise ValueError(f"Invalid duration format: {s}")

    value, unit = m.groups()
    return int(value) * UNIT_TO_SECONDS[unit]

def find_files(root: str, target_name: str) -> list[str]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        if target_name in filenames:
            result.append(os.path.join(dirpath, target_name))
    return len(result)


def parse_args():
    parser = argparse.ArgumentParser(description="Calulate average test count")
    parser.add_argument("--result-dir", required=True, help="Test result dir")
    parser.add_argument("--time", required=True, help="Test time (5m, 1h...)")
    args = parser.parse_args()

    return args


def main(args):
    duration = parse_duration(args.time)

    test_result_dir = f"{args.result_dir}/test_*"
    dirs = glob.glob(test_result_dir)

    tmp = []
    for d in dirs:
        count = find_files(d, "qemu_trace_log.log")
        tmp.append(count / duration)
    
    avg = sum(tmp) / len(tmp)
    print(f"Average exec/sec is {avg:.5}")

if __name__ == "__main__":
    main(parse_args())