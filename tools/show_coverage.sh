#!/bin/bash

if [ $# -ne 4 ]; then
    echo "[*]Usage $0 <path to trace log file> <path to binary file> <cross toolchain prefix> <base address>"
    exit 1
fi

logfile="$1"
binary="$2"
cross_prefix="$3"
base_address="$4"

trace_pcs=$(cat ${logfile})

for pc in ${trace_pcs[@]};
do
    addr=$(printf "0x%x" $((pc - base_address)))
    echo "${addr}" | "${cross_prefix}"addr2line -e "${binary}" -afp

done
