#!/usr/bin/env python3
import argparse
import csv

def read_coverage_csv(path):
    """
    Read CSV with format:
    Test No, Total Coverage(<type>)
    and return list of (test_no, coverage).
    """
    rows = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # skip header
        for r in reader:
            if not r:
                continue
            test_no = int(r[0])
            cov = float(r[1])
            rows.append((test_no, cov))
    return rows

def main():
    parser = argparse.ArgumentParser(
        description="Merge multi/single coverage CSV files into one."
    )
    parser.add_argument("--multi", required=True, help="CSV file for multi")
    parser.add_argument("--single", required=True, help="CSV file for single")
    parser.add_argument("--output", required=True, help="Output CSV filename")
    args = parser.parse_args()

    multi_rows = read_coverage_csv(args.multi)
    single_rows = read_coverage_csv(args.single)

    # Use the minimum length of both datasets
    min_len = min(len(multi_rows), len(single_rows))
    multi_rows = multi_rows[:min_len]
    single_rows = single_rows[:min_len]

    merged = []
    for i in range(min_len):
        test_no_m, cov_m = multi_rows[i]
        test_no_s, cov_s = single_rows[i]

        # If test numbers differ, use the one from multi and print a warning
        if test_no_m != test_no_s:
            print(
                f"Warning: Test No mismatch at index {i}: "
                f"multi={test_no_m}, single={test_no_s}. Using multi."
            )
        test_no = test_no_m
        merged.append((test_no, cov_m, cov_s))

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Test No", "Total Coverage(multi)", "Total Coverage(single)"])
        for test_no, cov_m, cov_s in merged:
            writer.writerow([test_no, cov_m, cov_s])

    print(f"Done. Wrote {args.output}")

if __name__ == "__main__":
    main()
