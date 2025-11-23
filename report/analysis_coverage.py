#!/usr/bin/env python3

import argparse
import csv
import os
from pathlib import Path

def check_switch_case_cover_result(csv_file_path: str, address_map: dict) -> dict:
    count = 0
    with open(csv_file_path, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
        reader.fieldnames = [name.strip() for name in reader.fieldnames]
        for row in reader:
            if row['Address'] in address_map:
                count += 1

    return count

def read_switch_case_address_map(csv_file_path: str) -> dict:
    address_map = {}
    print(f"[+]Reading switch case address map from {csv_file_path}")
    with open(csv_file_path, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
        reader.fieldnames = [name.strip() for name in reader.fieldnames]
        for row in reader:
            address = row['Address']
            address_map[address] = {
                'function': row['Function'],
                'file': row['Path'],
                'line': int(row['Line'])
            }
    return address_map

def write_output_csv(cover_results: dict, output_csv_path: str):
    with open(output_csv_path, mode='w', newline='') as csvfile:
        fieldnames = ['Test No', 'Multi Cover Count', 'Single Cover Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for test_no, results in cover_results.items():
            writer.writerow({
                'Test No': test_no,
                'Multi Cover Count': results['multi'],
                'Single Cover Count': results['single'],
            })
    print(f"[+]Coverage report written to {output_csv_path}")

def main():
    parser = argparse.ArgumentParser(description="Load switch case address map from CSV")
    parser.add_argument("--result-dir", help="Directory containing the CSV file", required=True)
    parser.add_argument("--address-map-csv", help="Path to the switch case address CSV file", required=True, default="switch_case_address.csv")
    parser.add_argument("--output-csv", help="Output CSV file path", required=False, default="switch_case_coverage_report.csv")
    args = parser.parse_args()

    address_map = read_switch_case_address_map(args.address_map_csv)

    path = Path(args.result_dir)

    dirs = sorted([p for p in path.iterdir() if p.is_dir()])

    cover_results = {}
    for d in dirs:
        test_no = "_".join(os.path.basename(d).split("_")[:2])
        cover_results[test_no] = {
            'single': {},
            'multi': {}
        }
        print(f"[+]Processing test directory: {d} (Test No: {test_no})")

        for test_type in ["multi", "single"]:
            csv_name = f"a2r_{test_type}.csv"
            csv_file = os.path.join(d, csv_name)
            count = check_switch_case_cover_result(csv_file, address_map)
            cover_results[test_no][test_type] = count


    write_output_csv(cover_results, args.output_csv)
if __name__ == "__main__":
    main()