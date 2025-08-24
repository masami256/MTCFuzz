#!/usr/bin/env python3
import argparse
import glob
import pprint

def output_results(filename, merged):
    with open(filename, "w") as f:
        f.write("Test No,Single Count,Single Rate,Multi Count,Multi Rate\n")
        for test_no, data in sorted(merged.items()):
            f.write(f"{test_no},{data['single_count']},{data['single_rate']},{data['multi_count']},{data['multi_rate']}\n")

    print(f"[+] Results written to {filename}")

def merge_data(single_data, multi_data):
    merged = {}

    all_keys = set(single_data.keys()) | set(multi_data.keys())

    for test_no in all_keys:
        merged[test_no] = {
            "single_count": single_data.get(test_no, {}).get("count", 0),
            "single_rate": single_data.get(test_no, {}).get("rate", 0.0),
            "multi_count": multi_data.get(test_no, {}).get("count", 0),
            "multi_rate": multi_data.get(test_no, {}).get("rate", 0.0),
        }

    return merged

def read_csv_files(dir, target_addresses):
    pattern = f"{dir}/*.csv"
    ret = {}

    files = sorted(glob.glob(pattern, recursive=True))

    for file in files:
        with open(file, "r") as f:
            test_no = int(file.split("/")[-1].split(".")[0].split("_")[0])
            ret[test_no] = {
                "count": 0,
                "rate": 0.0,
            }

            for line in f:
                line = line.strip()
                if not line:  # Skip empty lines
                    continue

                addr = line.split(",")[0].strip()
                if addr in target_addresses:
                    ret[test_no]["count"] += 1
            ret[test_no]["rate"] = ret[test_no]["count"] / len(target_addresses) if target_addresses else 0.0
    
    return ret

def read_target_addresses(file):
    ret = []

    with open(file, "r") as f:
        ret = [line.strip() for line in f if line.strip()]
    return ret

def parse_arguments():
    parser = argparse.ArgumentParser(description="Analyze address coverage rate from CSV files.")
    parser.add_argument("--single-dir", required=True, type=str, help="Path to the single test directory containing CSV files")
    parser.add_argument("--multi-dir", required=True, type=str, help="Path to the multi test directory containing CSV files")
    parser.add_argument("--target-addresses", required=True, type=str, help="Path to the file containing target addresses")
    parser.add_argument("--output-file", type=str, default="address_coverage_rate.csv", help="Path to the output file")

    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()

    target_addresses = read_target_addresses(args.target_addresses)

    single_data = read_csv_files(args.single_dir, target_addresses)
    multi_data = read_csv_files(args.multi_dir, target_addresses)

    merged = merge_data(single_data, multi_data)
    output_results(args.output_file, merged)
if __name__ == "__main__":
    main()