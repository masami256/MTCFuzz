#!/bin/sh

if [ $# != 1 ]; then
  echo "usage: $0 <normal|custome>"
  exit 1
fi

target="$1"
logdir="result_${target}"

mkdir "${logdir}"
mkdir "${logdir}/process"
mkdir "${logdir}/thread"

echo "[+]Start warmup"
hackbench -l 500 -g 5 --process
echo "[+]Finish warmup"

echo "[+]Start testing"
echo "[+]Start process test"
for i in $(seq 1 30);
do
    echo "[+]loop ${i}:Running process test"
    filename="${logdir}/process/test_${i}_${target}_${process}.txt"
    hackbench -l 2000 -g 10 --process 2>&1 >"${filename}"
done

echo "[+]Finish process test"
echo "[+]Start thread test"

for i in $(seq 1 30);
do
    echo "[+]loop ${i}:Running thread test"
    filename="${logdir}/thread/test_${i}_${target}_${thread}.txt"
    hackbench -l 2000 -g 10 --thread 2>&1 >"${filename}"
done
echo "[+]Finish thread test"

echo "[+]Done."