#!/bin/bash

if [ $# != 3 ]; then
    echo "Usage: $0 <config> <compare log dir> <number of tests>"
    exit 1
fi

config="$1"
compare_log_dir="$2"
num_tests="$3"

script_dir=$(realpath $(dirname "${BASH_SOURCE[0]}"))
mtcfuzz_top_dir=$(realpath ${script_dir}/../)
tools_dir="${mtcfuzz_top_dir}/tools"

for i in $(seq 1 ${num_tests});
do
    testno=$(printf "%05d" $i)
    output_dir="${compare_log_dir}/test_${testno}_compare_result"
    single_file=$(realpath "${compare_log_dir}/test_${testno}_compare_result/statics_single.csv")
    multi_file=$(realpath "${compare_log_dir}/test_${testno}_compare_result/statics_multi.csv")

    "${tools_dir}/addr2line.py" \
        --config "${config}" \
        --trace-log "${single_file}" \
        --output "${output_dir}/a2r_single.csv"

    "${tools_dir}/addr2line.py" \
        --config "${config}" \
        --trace-log "${multi_file}" \
        --output "${output_dir}/a2r_multi.csv"
done