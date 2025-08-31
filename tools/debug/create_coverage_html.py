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
            if len(row) != 4:
                continue
            addr, func, src_path, line_str = row
            if addr == "Address":
                continue
            try:
                line_num = int(line_str)
                key = f"{src_path}:{line_num}"
                ret[key] = {
                    "addr": addr,
                    "func": func,
                    "line": line_num,
                    "file": src_path,
                    "count": 1,
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


def write_html_per_file(output_dir, src_path, lines, coverage, prefix=""):
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
        f.write("tr.hit { background-color: #ddffdd; }\n")
        f.write("</style></head><body>\n")

        abs_src_path = os.path.abspath(src_path)
        abs_prefix = os.path.abspath(prefix) if prefix else ""
        display_path = abs_src_path[len(abs_prefix):].lstrip(os.sep) if abs_prefix and abs_src_path.startswith(abs_prefix) else src_path
        f.write(f"<h2>{html.escape(display_path)}</h2>\n")

        f.write("<div><strong>Legend:</strong><ul>\n")
        f.write("<li style='background-color:#ddffdd;'>Covered (count &gt; 0)</li>\n")
        f.write("<li>No coverage</li>\n")
        f.write("</ul></div><br>\n")

        f.write("<table>\n")
        f.write("<tr><th>Count</th><th>Line</th><th>Source</th></tr>\n")

        for lineno in sorted(lines.keys()):
            key = f"{src_path}:{lineno}"
            line_text = html.escape(lines[lineno])
            count = coverage.get(key, {}).get("count", 0)
            display = str(count) if count > 0 else "&nbsp;"

            row_class = "hit" if count > 0 else ""
            f.write(f"<tr class='{row_class}'>")
            f.write(f"<td class='count'>{display}</td>")
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
    parser = argparse.ArgumentParser(description="Generate HTML coverage report (single CSV).")
    parser.add_argument("--csv", required=True, help="Path to coverage CSV")
    parser.add_argument("--html-dir", required=True, help="Output directory for HTML files")
    parser.add_argument("--prefix", help="Prefix path to strip from source paths in frame list", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    coverage = read_csv(args.csv)

    all_files = set()
    for key in coverage.keys():
        src_path, _ = key.rsplit(":", 1)
        all_files.add(src_path)

    source_lines = create_source_line_map(all_files)
    os.makedirs(args.html_dir, exist_ok=True)

    for src_path in sorted(source_lines.keys()):
        write_html_per_file(
            args.html_dir,
            src_path,
            source_lines[src_path],
            coverage,
            prefix=args.prefix
        )

    write_frame_list(args.html_dir, source_lines.keys(), prefix=args.prefix)
    write_frame_index(args.html_dir)

    print(f"HTML coverage report generated in: {args.html_dir}/index.html")


if __name__ == "__main__":
    main()
