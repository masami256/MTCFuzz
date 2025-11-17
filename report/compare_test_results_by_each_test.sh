#!/bin/bash

if [ $# != 4 ]; then
    echo "Usage: $0 <multi test result dir> <single test result dir> <number of tests> <output dir>"
    exit 1
fi

multi_dir="$1"
single_dir="$2"
num_tests="$3"

output_dir_base="$4"

if [ ! -d "${output_dir_base}" ]; then
    mkdir "${output_dir_base}"
fi

script_dir=$(realpath $(dirname "${BASH_SOURCE[0]}"))
mtcfuzz_top_dir=$(realpath ${script_dir}/../)
report_tool_dir="${mtcfuzz_top_dir}/report"

for i in $(seq 1 ${num_tests});
do
    testno=$(printf "%05d" $i)
    multi_result_dir=$(realpath "${multi_dir}/test_${testno}")
    single_result_dir=$(realpath "${single_dir}/test_${testno}")
    output_dir="${output_dir_base}/test_${testno}_compare_result"

    mkdir -p "${output_dir}"

    "${report_tool_dir}/compare_test_results.py" \
        --single "${single_result_dir}" \
        --multi "${multi_result_dir}" \
        --output-dir "${output_dir}"
done
