#!/bin/bash

if [ $# != 2 ]; then
    echo "Usage: $0 <compare result dir> <number of tests>"
    exit 1
fi

compare_result_dir="$1"
num_tests="$2"

script_dir=$(realpath $(dirname "${BASH_SOURCE[0]}"))
mtcfuzz_top_dir=$(realpath ${script_dir}/../)
report_tool_dir="${mtcfuzz_top_dir}/report"


for i in $(seq 1 ${num_tests});
do
    testno=$(printf "%05d" $i)
    compare_result_dir_by_testno="${compare_result_dir}/test_${testno}_compare_result"
    output_dir="${compare_result_dir_by_testno}/html_report"

    "${report_tool_dir}/create_coverage_result_html.py" \
        --single "${compare_result_dir_by_testno}/a2r_single.csv" \
        --multi "${compare_result_dir_by_testno}/a2r_multi.csv" \
        --html-dir "${output_dir}"
done
