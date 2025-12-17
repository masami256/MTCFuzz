#!/usr/bin/env python3
import os
from pathlib import Path
import argparse
import json
from bisect import bisect_right

QEMU_TRACE_LOG_FILE = "qemu_trace_log.log"


def write_csv(output_filename: str, coverages: dict[int, dict]) -> None:
    """
    Write CSV lines: test_no,new_count,cumulative_count
    """
    cumulative = 0
    with open(output_filename, "w") as f:
        for test_no in sorted(coverages):
            d = coverages[test_no]
            cumulative += d["new_count"]
            f.write(f"{d['test_no']},{d['new_count']},{cumulative}\n")


def addr_in_filters(addr: int, filters: list[tuple[int, int]], starts: list[int]) -> bool:
    """
    Return True if addr is inside any non-overlapping, sorted [lower, upper] ranges.
    Assumption: filters are merged (non-overlapping) and sorted by lower bound.
    """
    idx = bisect_right(starts, addr) - 1
    if idx < 0:
        return False
    lower, upper = filters[idx]
    return lower <= addr <= upper


def apply_filter(
    trace_logs: list[str],
    filters: list[tuple[int, int]],
    starts: list[int],
    coverages: dict[int, dict],
    test_no: int,
    seen_addrs: set[int],
) -> None:
    """
    Count newly discovered addresses in this test:
      - Only addresses inside the filters are considered.
      - An address is "new" if it has not appeared in any previous test.
      - Multiple occurrences of the same address in the same test are counted once.
    """
    new_addrs: set[int] = set()

    for line in trace_logs:
        addr_s = line.strip()
        try:
            addr = int(addr_s, 16)
        except Exception:
            # Skip malformed lines
            continue

        # Skip addresses outside of the filter ranges
        if not addr_in_filters(addr, filters, starts):
            continue

        # Skip addresses already seen in earlier tests
        if addr in seen_addrs:
            continue

        # Record as newly discovered in this test (deduplicate within the test)
        new_addrs.add(addr)

    # Update global seen set after processing this test
    seen_addrs.update(new_addrs)

    coverages[test_no] = {
        "test_no": test_no,
        "new_count": len(new_addrs),
    }


def read_qemu_trace_log(filename: Path) -> list[str]:
    """
    Read qemu_trace_log.log and return lines.
    """
    with open(filename) as f:
        return f.readlines()


def create_merged_filter(config: dict, target_filter) -> list[tuple[int, int]]:
    """
    Create a merged filter list from config["address_filters"]["kernel"/"firmware"].
    NOTE: This function assumes the final list is non-overlapping after sort.
          (User stated filters are already merged/non-overlapping.)
    """
    result: list[tuple[int, int]] = []

    address_filters = config["address_filters"]
    targets = None
    if target_filter == "all":
        filters = ["kernel", "firmware"]
    elif target_filter == "kernel":
        filters = ["kernel"]
    elif target_filter == "firmware":
        filters = ["firmware"]
    else:
        print(f"Unknown filter type {target_filter}")
        exit(1)

    for group in filters:
        for data in address_filters[group]:
            lower = int(data["lower"], 16)
            upper = int(data["upper"], 16)
            result.append((lower, upper))

    result.sort(key=lambda x: x[0])
    return result


def read_config(config_path: str) -> dict:
    """
    Load JSON config.
    """
    with open(config_path) as f:
        return json.load(f)


def main(args: argparse.Namespace) -> None:
    coverages: dict[int, dict] = {}
    seen_addrs: set[int] = set()

    config = read_config(args.config)

    filters = create_merged_filter(config, args.target_filter)
    starts = [lower for (lower, _) in filters]

    base_dir = Path(os.path.abspath(args.result_dir))
    files = sorted(base_dir.rglob(QEMU_TRACE_LOG_FILE))

    for test_no, file in enumerate(files):
        print(f"[+] Processing {file}")
        trace_logs = read_qemu_trace_log(file)
        apply_filter(trace_logs, filters, starts, coverages, test_no, seen_addrs)

    write_csv(args.output, coverages)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="New coverage address counter")
    parser.add_argument("--config", required=True, help="Config JSON file")
    parser.add_argument("--result-dir", required=True, help="Path to test result directory")
    parser.add_argument("--output", required=True, help="Output CSV file name")
    parser.add_argument("--target-filter", default="all", help="all/kernel/firmware")
    return parser.parse_args()


if __name__ == "__main__":
    main(parse_args())
