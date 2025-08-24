#!/usr/bin/env python3

import argparse
import csv
import os
import html
import collections


def read_csv(file_path):
    ret = {}
    with open(file_path, newline="") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) != 5:
                continue
            addr, func, src_path, line_str, count_str = row
            if addr == "Address":
                continue
            try:
                line_num = int(line_str)
                key = f"{src_path}:{line_num}"
                ret[key] = {
                    "addr": addr,
                    "func": func,
                    "count": int(count_str) if count_str.isdigit() else 0,
                    "line": line_num,
                    "src_path": src_path,
                }
            except ValueError:
                continue
    return ret


def create_source_line_map(file_paths):
    result = {}
    for filepath in file_paths:
        try:
            with open(filepath, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            continue
        line_map = {}
        for idx, line in enumerate(lines):
            line_map[idx + 1] = line.replace("\t", "    ").rstrip("\n")
        result[filepath] = line_map
    return result


def sanitize_filename(filepath):
    """Convert full path to a safe unique HTML filename."""
    rel_path = os.path.relpath(filepath).replace(os.sep, "_")
    return rel_path.replace(".", "_") + ".html"


def write_html_per_file(output_dir, src_path, lines, single_coverage, multi_coverage, prefix=""):
    dst_file = os.path.join(output_dir, sanitize_filename(src_path))
    with open(dst_file, "w") as f:
        f.write("<html><head><style>\n")
        f.write("body { font-family: monospace; background-color: #fdfdfd; }\n")
        f.write("table { border-collapse: collapse; margin-bottom: 30px; }\n")
        f.write("td, th { padding: 4px 8px; vertical-align: top; }\n")
        f.write("tr:nth-child(even) { background-color: #f9f9f9; }\n")
        f.write(".count { text-align: right; width: 60px; color: #555; }\n")
        f.write(".line { white-space: pre; }\n")
        f.write("th { background-color: #eaeaea; font-weight: bold; }\n")
        f.write("tr.both-hit { background-color: #ddffdd; }\n")
        f.write("tr.multi-only { background-color: #ddeeff; }\n")
        f.write("tr.single-only { background-color: #ffe4b3; }\n")
        f.write("</style></head><body>\n")

        abs_src_path = os.path.abspath(src_path)
        abs_prefix = os.path.abspath(prefix) if prefix else ""
        display_path = abs_src_path[len(abs_prefix):].lstrip(os.sep) if abs_src_path.startswith(abs_prefix) else src_path
        f.write(f"<h2>{html.escape(display_path)}</h2>\n")

        f.write("<div><strong>Legend:</strong><ul>\n")
        f.write("<li style='background-color:#ddffdd;'>Covered by both single and multi</li>\n")
        f.write("<li style='background-color:#ddeeff;'>Covered only by multi</li>\n")
        f.write("<li style='background-color:#ffe4b3;'>Covered only by single</li>\n")
        f.write("<li>No coverage</li>\n")
        f.write("</ul></div><br>\n")

        f.write("<table>\n")
        f.write("<tr><th>Multi</th><th>Single</th><th>Line</th><th>Source</th></tr>\n")

        for lineno in sorted(lines.keys()):
            key = f"{src_path}:{lineno}"
            line_text = html.escape(lines[lineno])
            multi_count = multi_coverage.get(key, {}).get("count", 0)
            single_count = single_coverage.get(key, {}).get("count", 0)
            multi_display = str(multi_count) if multi_count > 0 else "&nbsp;"
            single_display = str(single_count) if single_count > 0 else "&nbsp;"

            if multi_count > 0 and single_count > 0:
                row_class = "both-hit"
            elif multi_count > 0:
                row_class = "multi-only"
            elif single_count > 0:
                row_class = "single-only"
            else:
                row_class = ""

            f.write(f"<tr class='{row_class}'>")
            f.write(f"<td class='count'>{multi_display}</td>")
            f.write(f"<td class='count'>{single_display}</td>")
            f.write(f"<td class='count'>{lineno}</td>")
            f.write(f"<td class='line'>{line_text}</td>")
            f.write("</tr>\n")

        f.write("</table>\n</body></html>\n")


def build_tree_with_display(display_paths, real_paths):
    Tree = lambda: collections.defaultdict(Tree)
    root = Tree()
    for display_path, real_path in zip(display_paths, real_paths):
        parts = display_path.strip(os.sep).split(os.sep)
        current = root
        for part in parts:
            current = current[part]
        current["__fullpath__"] = real_path
    return root


def write_frame_list(output_dir, src_paths, prefix=""):
    prefix = os.path.abspath(prefix) if prefix else ""

    def strip_prefix(path):
        abs_path = os.path.abspath(path)
        if prefix and abs_path.startswith(prefix):
            return abs_path[len(prefix):].lstrip(os.sep)
        return abs_path

    display_paths = [strip_prefix(p) for p in src_paths]
    tree = build_tree_with_display(display_paths, src_paths)
    outpath = os.path.join(output_dir, "frame_list.html")

    def render_node(node, f):
        f.write("<ul>\n")
        for name in sorted(node.keys()):
            if name == "__fullpath__":
                continue
            child = node[name]
            fullpath = child.get("__fullpath__")
            if fullpath:
                link = sanitize_filename(fullpath)
                display_name = os.path.relpath(fullpath, prefix) if prefix and fullpath.startswith(prefix) else fullpath
                filename = os.path.basename(display_name)
                f.write(f"<li><a href='{link}' target='sourceview'>{html.escape(filename)}</a></li>\n")
            else:
                f.write(f"<li><details open><summary>{html.escape(name)}</summary>\n")
                render_node(child, f)
                f.write("</details></li>\n")
        f.write("</ul>\n")

    with open(outpath, "w") as f:
        f.write("<html><head><style>\n")
        f.write("body { font-family: sans-serif; padding: 8px; }\n")
        f.write("ul { list-style-type: none; padding-left: 1em; }\n")
        f.write("li { margin: 4px 0; }\n")
        f.write("a { text-decoration: none; color: #004080; }\n")
        f.write("summary { cursor: pointer; font-weight: bold; }\n")
        f.write("</style></head><body>\n")
        render_node(tree, f)
        f.write("</body></html>\n")


def write_frame_index(output_dir):
    index_file = os.path.join(output_dir, "index.html")
    with open(index_file, "w") as f:
        f.write("<html><head><title>Coverage Viewer</title></head>\n")
        f.write("<frameset cols='25%,75%'>\n")
        f.write("<frame src='frame_list.html' name='filelist'>\n")
        f.write("<frame src='about:blank' name='sourceview'>\n")
        f.write("</frameset></html>\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Generate HTML coverage report.")
    parser.add_argument("--single", required=True, help="Path to single coverage CSV")
    parser.add_argument("--multi", required=True, help="Path to multi coverage CSV")
    parser.add_argument("--html-dir", required=True, help="Output directory for HTML files")
    parser.add_argument("--prefix", help="Prefix path to strip from source paths in frame list", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    single_coverage = read_csv(args.single)
    multi_coverage = read_csv(args.multi)

    all_files = set()
    for key in set(single_coverage.keys()).union(set(multi_coverage.keys())):
        src_path, _ = key.rsplit(":", 1)
        all_files.add(src_path)

    source_lines = create_source_line_map(all_files)
    os.makedirs(args.html_dir, exist_ok=True)

    for src_path in sorted(source_lines.keys()):
        write_html_per_file(args.html_dir, src_path, source_lines[src_path],
            single_coverage, multi_coverage, prefix=args.prefix)

    write_frame_list(args.html_dir, source_lines.keys(), prefix=args.prefix)
    write_frame_index(args.html_dir)

    print(f"HTML coverage report generated in: {args.html_dir}/index.html")


if __name__ == "__main__":
    main()
