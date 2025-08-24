#!/bin/bash

export PYTHONPATH=/home/build/projects/srcs/qemu/python
export PYTHONPYCACHEPREFIX=/tmp/fuzz_cache

if [ $# != 7 ]; then
    echo "Usage: $0 <multi|single> <loop num> <base address> <config json> <test result dir> <output dir> <path to addr2line>"
    echo "Example: $0 multi 10 0x80000000 ./configs/opensbi/coverage_test/coverage_test_single_check_config.json test_result_base_ecall_cover_test /tmp/trace_report" /home/build/projects/srcs/optee/toolchains/aarch64/bin/aarch64-linux-gnu-addr2line
    exit 1
fi

check_type="$1"
num_loop="$2"
base_adddr="$3"
config_path=$(realpath "$4")
test_result_path=$(realpath "$5")

mkdir -p "$6"
output_dir=$(realpath "$6")

addr2line="$7"

for i in $(seq 1 $num_loop); do
    ./tools/addr2line.py --base-addr ${base_adddr} \
      --config-json ${config_path} \
      --trace-log ${test_result_path}/${check_type}_results/$(printf '%05d' "$i")_cover-${check_type}.csv \
      --output ${output_dir}/$(printf '%05d' "$i")_cover-${check_type}_src_info.csv \
      --addr2line ${addr2line}
done
