#!/bin/bash

SCRIPT_PATH="$(realpath "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
MTCFUZZ_ROOT_DIR=$(realpath ${SCRIPT_DIR}/../..)
WORKDIR="${MTCFUZZ_ROOT_DIR}/filter_test_work_dir"

cd "${MTCFUZZ_ROOT_DIR}"

if [ -d "${WORKDIR}" ]; then
    rm -fr "${WORKDIR}"
fi
mkdir "${WORKDIR}"

# Create target list
find /home/build/projects/srcs/linux/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"


echo "[+]Create template config.json"
OUTPUT_CONFIG_FILENAME="${WORKDIR}/tmp-filter-config.json"

./tools/create_address_filter.py --target-list "${WORKDIR}/riscv-kernel-files.txt"  \
    --objdump /usr/bin/riscv64-linux-gnu-objdump \
    --binary ~/projects/srcs/linux/vmlinux \
    --output "${OUTPUT_CONFIG_FILENAME}" \
    --config ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json \
    --replace \
    --filter-target kernel || exit

max_filters="all-functions"

echo "[+]Test max filters: all functions"

for i in $(seq 1 3);
do
    echo "[+]Run test ${i}"
    RESULT_FILENAME="${WORKDIR}/address_filters_test_result_${i}.csv"
    if [ -e "${RESULT_FILENAME}" ]; then
        rm -f "${RESULT_FILENAME}"
    fi
    echo "number of filters, test count" > "${RESULT_FILENAME}"

    TEST_DIR="${WORKDIR}/test_result_${max_filters}_filters_test_${i}"

    if [ -d "${TEST_DIR}" ]; then
        rm -fr "${TEST_DIR}"
    fi

    ./tests/run-fuzz.sh "${OUTPUT_CONFIG_FILENAME}" "${TEST_DIR}" 10m 1

    test_count=$(find "${TEST_DIR}" -name "qemu_trace_log.log" | wc -l)
    echo "${max_filters},${test_count}" >> "${RESULT_FILENAME}"
done

echo "[+]Done."

