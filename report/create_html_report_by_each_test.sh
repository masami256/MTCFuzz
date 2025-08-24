#!/bin/bash

export PYTHONPATH=/home/build/projects/srcs/qemu/python
export PYTHONPYCACHEPREFIX=/tmp/fuzz_cache

if [ $# != 3 ]; then
    echo "Usage: $0 <loop num> <trace log base dir> <output dir>"
    echo "Example: $0 10 /tmp/trace_log_base /tmp/html_report"
    exit 1
fi

num_loop="$1"
trace_log_base_dir=$(realpath "$2")
output_dir=$(realpath "$3")

for i in $(seq 1 $num_loop); do
    mkdir -p ${output_dir}/test_$(printf '%05d' "$i")

    ./report/create_coverage_result_html.py \
    --single ${trace_log_base_dir}/single/$(printf '%05d' "$i")_cover-single_src_info.csv \
    --multi ${trace_log_base_dir}/multi/$(printf '%05d' "$i")_cover-multi_src_info.csv \
    --html-dir ${output_dir}/test_$(printf '%05d' "$i")

done
