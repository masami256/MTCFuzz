#!/usr/bin/env python3

import argparse
import glob
import os
import pprint

def analyze_data(files):
    ret = {}

    for file in files:
        with open(file, "r") as f:
            for line in f:
                line = line.strip()
                tmp = line.split(",")
                addr = tmp[0]
                count = int(tmp[1])

                if addr not in ret:
                    ret[addr] = count
                else:
                    ret[addr] += count
    return ret

def parse_arguments():
    parser = argparse.ArgumentParser(description="Compare test results from two directories.")
    parser.add_argument("--single", required=True, type=str, help="Path to the single coverage test result directory")
    parser.add_argument("--multi", required=True, type=str, help="Path to the multi coverage test result directory")
    parser.add_argument("--output-dir", type=str, default="compare_results", help="Path to the output directory")

    args = parser.parse_args()
    return args

def collect_files(directory):
    pattern = f"{directory}/*.csv"
    ret = []

    for file in glob.glob(pattern, recursive=True):
        ret.append(file)
    
    return ret

def output_results(filename, data):
    with open(filename, "w") as f:
        f.write("Address,Count\n")
        for addr, count in sorted(data.items(), key=lambda x: int(x[0], 16)):
            f.write(f"{addr},{count}\n")

    print(f"[+] Results written to {filename}")

def main():
    args = parse_arguments()

    single_result_files = collect_files(args.single)
    multi_result_files = collect_files(args.multi)

    anlyzed_single = analyze_data(single_result_files)
    anlyzed_multi = analyze_data(multi_result_files)

    only_in_single = {k: anlyzed_single[k] for k in anlyzed_single.keys() - anlyzed_multi.keys()}
    only_in_multi = {k: anlyzed_multi[k] for k in anlyzed_multi.keys() - anlyzed_single.keys()}

    if only_in_single:
        print("[+] Addresses only in single coverage test:")
        pprint.pprint(only_in_single)
    
    if only_in_multi:
        print("[+] Addresses only in multi coverage test:")
        pprint.pprint(only_in_multi)
        
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    single_result_file = os.path.join(args.output_dir, "statics_single.csv")
    multi_result_file = os.path.join(args.output_dir, "statics_multi.csv")
    single_only_file = os.path.join(args.output_dir, "only_in_single.csv")
    multi_only_file = os.path.join(args.output_dir, "only_in_multi.csv")

    output_results(single_result_file, anlyzed_single)
    output_results(multi_result_file, anlyzed_multi)
    output_results(single_only_file, only_in_single)
    output_results(multi_only_file, only_in_multi)
    
    print("[+] Analysis completed.")
if __name__ == "__main__":
    main()
    