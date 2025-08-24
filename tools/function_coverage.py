#!/usr/bin/env python3
import argparse
from collections import namedtuple, defaultdict
import csv
import os

FunctionRange = namedtuple("FunctionRange", ["name", "file", "start", "end"])

def parse_ctags_extended(tags_file, source_root):
    functions = []
    with open(tags_file) as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 5 or parts[3] != "f":
                continue

            func_name = parts[0]
            if source_root:
                file_path = os.path.abspath(os.path.join(source_root, parts[1]))
            else:
                file_path = os.path.abspath(parts[1])

            start_line = None
            for p in parts[4:]:
                if p.startswith("line:"):
                    start_line = int(p[len("line:"):])
                    break

            if start_line is not None:
                functions.append((file_path, func_name, start_line))

    file_to_funcs = defaultdict(list)
    for file_path, func_name, start_line in functions:
        file_to_funcs[file_path].append((start_line, func_name))

    func_ranges = []
    for file_path, funcs in file_to_funcs.items():
        funcs.sort()
        for i, (start, name) in enumerate(funcs):
            if i + 1 < len(funcs):
                end = funcs[i + 1][0] - 1
            else:
                try:
                    with open(file_path) as f:
                        end = sum(1 for _ in f)
                except FileNotFoundError:
                    end = start
            func_ranges.append(FunctionRange(name, file_path, start, end))
    return func_ranges

def parse_addr2line_csv(addr_file):
    hits = defaultdict(set)  # (abs_path, function) → set(line)
    with open(addr_file) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != 5:
                continue
            _, func, path, exec_line, _ = row
            try:
                abs_path = os.path.abspath(path)
                hits[(abs_path, func)].add(int(exec_line))
            except ValueError:
                continue
    return hits

def calculate_function_hit_only(func_ranges, hits, output_file_prefix):
    file_summary = defaultdict(lambda: {"total": 0, "covered": 0})

    file_covers = []
    for fr in func_ranges:
        key = (fr.file, fr.name)
        file_summary[fr.file]["total"] += 1

        if key in hits:
            file_summary[fr.file]["covered"] += 1
            file_covers.append((fr.file, fr.name, "Covered"))
        else:
            file_covers.append((fr.file, fr.name, "Not covered"))

    total_summary = []
    for file, summary in file_summary.items():
        total = summary["total"]
        covered = summary["covered"]
        rate = (covered / total) * 100 if total > 0 else 0.0
        total_summary.append([file, total, covered, rate])

    with open(f"{output_file_prefix}_function_coverages.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "Function", "Coverage"])
        for file, func, status in file_covers:
            writer.writerow([file, func, status])

    with open(f"{output_file_prefix}_file_summary.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(["File", "Total Functions", "Covered", "Coverage Rate"])
        for file, total, covered, rate in total_summary:
            writer.writerow([file, total, covered, rate])

def main():
    parser = argparse.ArgumentParser(description="Report function coverage (hit-based only) from ctags and addr2line CSV.")
    parser.add_argument("--tag-file", dest="tags_file", required=True)
    parser.add_argument("--addr-file", dest="addr_file", required=True)
    parser.add_argument("--source-root", dest="source_root", default=None, help="Root of the source code")
    parser.add_argument("--output", dest="output_file", default="function_coverage", help="Output file name prefix")

    args = parser.parse_args()

    func_ranges = parse_ctags_extended(args.tags_file, args.source_root)
    addr_hits = parse_addr2line_csv(args.addr_file)

    output_file_prefix = args.output_file if args.output_file is not None else "function_coverage"
    calculate_function_hit_only(func_ranges, addr_hits, output_file_prefix)

if __name__ == "__main__":
    main()
