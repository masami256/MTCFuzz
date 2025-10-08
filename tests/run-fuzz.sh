#!/bin/bash
set -e

export PYTHONPATH=/home/build/projects/srcs/qemu/python
export PYTHONPYCACHEPREFIX=/tmp/fuzz_cache

script_dir=$(realpath $(dirname "${BASH_SOURCE[0]}"))
mtcfuzz_top_dir=$(realpath ${script_dir}/../)
fuzzer_dir="${mtcfuzz_top_dir}/fuzzer"

if [ $# != 4 ]; then
    echo "Usage: $0 <config> <result dir> <fuzzing_execution_time> <num_tests> "
    echo "Example: $0 /path/to/config.json ./test_result 2m 10"
    exit 1
fi

config=$(realpath $1)
result_dir="$2"
fuzzing_execution_time="$3"
num_tests="$4"

workdir=$(realpath $(jq -r .fuzzing.local_work_dir "${config}"))

echo "Fuzzing execution time: $fuzzing_execution_time"
echo "config: $config"

cd ${mtcfuzz_top_dir}

if [ -e "${result_dir}" ]; then
    rm -fr "${result_dir}"
fi
mkdir -p "${result_dir}"

result_dir=$(realpath ${result_dir})

config_file_name=$(basename ${config})
cp "${config}" "${result_dir}/${config_file_name}"

cd "${fuzzer_dir}"

for i in $(seq 1 $num_tests); do
    test_num=$(printf '%05d' "$i")
    echo "Loop $i of $num_tests"

    current_test_result_dir="${result_dir}/test_${test_num}"
    mkdir -p "${current_test_result_dir}"

    rm -fr "${workdir}" ; mkdir "${workdir}"

    echo "start: $(date)" > "${workdir}/test_${test_num}_start_time.txt"
    timeout "${fuzzing_execution_time}" ./main.py --config "${config}" || true
    echo "end: $(date)" > "${workdir}/test_${test_num}_end_time.txt"

    cp -a "${workdir}" "${current_test_result_dir}/test_${test_num}_work_dir"
    echo "work directory(${workdir}) was copied to ${current_test_result_dir}/test_${test_num}_work_dir"
done

echo "Done"
