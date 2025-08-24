#!/bin/bash

export PYTHONPATH=/home/build/projects/srcs/qemu/python
export PYTHONPYCACHEPREFIX=/tmp/fuzz_cache

if [ $# != 4 ]; then
    echo "Usage: $0 <config> <multi|single><fuzzing_execution_time> <num_loop>"
    echo "Example: $0 /path/to/config.json multi 2m 10"
    exit 1
fi

config=$(realpath $1)
check_type="$2"
fuzzing_execution_time="$3"
num_loop="$4"

echo "Fuzzing execution time: $fuzzing_execution_time"
echo "config: $config"

script_dir=$(realpath $(dirname "$0"))
cd $script_dir

cd ../../../fuzzer

result_dir="../test_result_eid_search_test/${check_type}_results"
rm -fr "${result_dir}" ; mkdir -p "${result_dir}"

for i in $(seq 1 $num_loop); do
    echo "Loop $i of $num_loop"
    rm -fr ../work/*
    echo "start: $(date)" > "../work/test_$(printf '%05d' "$i")_start_time.txt"
    timeout "${fuzzing_execution_time}" ./main.py --config "${config}"
    echo "end: $(date)" > "../work/test_$(printf '%05d' "$i")_end_time.txt"
    ../report/coverage-report.py --output "${result_dir}/$test_$(printf '%05d' "$i")_cover-${check_type}.csv" \
        --config-json "../configs/opensbi/eid_test/eid_test_${check_type}_check_config.json" --check-firmware-coverage --check-kernel-coverage
done

echo "Done"
