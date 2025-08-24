#!/bin/bash

export PYTHONPATH=/home/build/projects/srcs/qemu/python
export PYTHONPYCACHEPREFIX=/tmp/fuzz_cache

if [ $# != 2 ]; then
    echo "Usage: $0 <config> <fuzzing_execution_time>"
    echo "Example: $0 /path/to/config.json 2m"
    exit 1
fi

config=$(realpath $1)
fuzzing_execution_time="$2"
kill -kill $(pgrep qemu)

echo "Fuzzing execution time: $fuzzing_execution_time"
echo "config: $config"

script_dir=$(realpath $(dirname "$0"))
cd $script_dir

rm -fr work || true
mkdir work
cd fuzzer

echo "start: $(date)" > ../work/start_time.txt
timeout "${fuzzing_execution_time}" ./main.py --config "$config"
echo "end: $(date)" > ../work/end_time.txt

echo "Done"
