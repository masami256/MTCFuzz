#!/bin/bash

export PYTHONPATH=/home/build/projects/srcs/qemu/python
export PYTHONPYCACHEPREFIX=/tmp/fuzz_cache

script_dir=$(realpath $(dirname "${BASH_SOURCE[0]}"))
mtcfuzz_top_dir=$(realpath ${script_dir}/../)
report_tool_dir="${mtcfuzz_top_dir}/report"

if [ $# -ne 2 ]; then
    echo "[*]Usage: $0 <config json> <test result dir>"
    echo "e.g: $0 myconfig.json test_result/"
    exit 1
fi

config=$(realpath "$1")
test_result_dir=$(realpath "$2")

echo "[+]Test result dir: ${test_result_dir}"
test_result_dirs=$(find "${test_result_dir}" -name "*_work_dir" -a -type d | sort)

for trd in $test_result_dirs; do
    echo "[+]Start processing directory: ${trd}"
    coverage_result_dir=$(dirname "${trd}")
    "${report_tool_dir}/coverage-report.py" \
        --output "${trd}_coverage_collected.csv" \
        --config-json "${config}" \
        --test-result-dir "${trd}" \
        --check-firmware-coverage \
        --check-kernel-coverage
    echo "[+]Finish processing directory: ${trd}"
done
