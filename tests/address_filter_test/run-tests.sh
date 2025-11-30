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
find /home/build/projects/srcs/linux/arch/riscv/ -name "*.o" > "${WORKDIR}/riscv-kernel-files.txt"
find /home/build/projects/srcs/linux/kernel/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"
find /home/build/projects/srcs/linux/ipc/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"
find /home/build/projects/srcs/linux/lib/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"
find /home/build/projects/srcs/linux/mm/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"
find /home/build/projects/srcs/linux/fs/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"
find /home/build/projects/srcs/linux/drivers/ -name "*.o" >> "${WORKDIR}/riscv-kernel-files.txt"

echo "[+]Create template config.json"
TMP_OUTPUT_FILENAME="${WORKDIR}/tmp-filter-config.json"
./tools/create_address_filter.py --target-list "${WORKDIR}/riscv-kernel-files.txt"  \
    --objdump /usr/bin/riscv64-linux-gnu-objdump \
    --binary ~/projects/srcs/linux/vmlinux \
    --output "${TMP_OUTPUT_FILENAME}" \
    --config ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json \
    --replace \
    --filter-target kernel || exit

RESULT_FILENAME="${WORKDIR}/address_filters_test_result.csv"
if [ -e "${RESULT_FILENAME}" ]; then
    rm -f "${RESULT_FILENAME}"
fi
echo "number of filters, test count" > "${RESULT_FILENAME}"

MAX_FILTERS=(2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768)
for max_filters in "${MAX_FILTERS[@]}";
do
    echo "[+]Test max filters: ${max_filters}"
    OUTPUT_CONFIG_FILENAME="${WORKDIR}/filter-test-${max_filters}-filters-config.json"
    
    TEST_DIR="${WORKDIR}/test_result_${max_filters}_filters_test"

    ./tests/address_filter_test/create_config.py --input "${TMP_OUTPUT_FILENAME}" --output "${OUTPUT_CONFIG_FILENAME}" --max-filters "${max_filters}" || exit
    
    if [ -d "${TEST_DIR}" ]; then
        rm -fr "${TEST_DIR}"
    fi

    ./tests/run-fuzz.sh "${OUTPUT_CONFIG_FILENAME}" "${TEST_DIR}" 10m 1

    test_count=$(find "${TEST_DIR}" -name "qemu_trace_log.log" | wc -l)
    echo "${max_filters},${test_count}" >> "${RESULT_FILENAME}"
done

echo "[+]Done."

