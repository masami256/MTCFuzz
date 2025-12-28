#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
import statistics

def read_csv(filepath):
    """Read each CSV and return list of (test_no, total_coverage)."""
    rows = []
    with open(filepath, newline="") as f:
        reader = csv.reader(f)
        for r in reader:
            if not r:
                continue
            test_no = int(r[0])
            total = int(r[2])   # <-- use 3rd column
            rows.append((test_no, total))
    return rows

def main():
    parser = argparse.ArgumentParser(
        description="Compute average total coverage across multiple CSV files"
    )
    parser.add_argument("--input-dir", required=True, help="Directory containing CSV files")
    parser.add_argument("--output", required=True, help="Output CSV filename")
    parser.add_argument(
        "--type",
        required=True,
        choices=["multi", "single"],
        help="Test type label (multi or single)"
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    csv_files = sorted(input_dir.glob("*.csv"))

    if not csv_files:
        print("No CSV files found.")
        return

    datasets = [read_csv(f) for f in csv_files]

    # Shortest test length determines aggregation range
    min_len = min(len(d) for d in datasets)
    datasets = [d[:min_len] for d in datasets]

    results = []
    for i in range(min_len):
        test_no = datasets[0][i][0]
        values = [d[i][1] for d in datasets]
        avg_total = statistics.mean(values)
        results.append((test_no, avg_total))

    header = ["Test No", f"Total Coverage({args.type})"]

    with open(args.output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for test_no, avg_val in results:
            writer.writerow([test_no, avg_val])

    print(f"Done. Wrote {args.output}")

if __name__ == "__main__":
    main()
