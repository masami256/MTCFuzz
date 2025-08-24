# OpenSBI ecall test

## Run

Run the test by executing tests/opensbi/base_ecall_coverage_test/run-fuzz.sh, which runs fuzzer/main.py to perform fuzzing and report/coverage-report.py to collect the coverage logs.

#### Run single coverage trace test.

```
./tests/opensbi/base_ecall_coverage_test/run-fuzz.sh ./configs/opensbi/coverage_test/coverage_test_single_check_config.json single 5m 10
```

#### Run multi coverage trace test.

```
./tests/opensbi/base_ecall_coverage_test/run-fuzz.sh ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json multi 5m 10
```

#### Collect single and multi fuzzing result

Run report/compare_test_results.py to collect logs.

```
./report/compare_test_results.py --single ./test_result_base_ecall_cover_test/single_results/ --multi  ./test_result_base_ecall_cover_test/multi_results/ --output-dir compare_result
```

### Analyze

Coverage trace log will be stored in the test_result_base_ecall_cover_test/\[single|multi\]_results directory.

#### Run addr2line to get source code information

Run tools/addr2line.py to get source code information.

##### Single coverage

For total coverage.

```
./tools/addr2line.py --base-addr 0x80000000 --config-json ./configs/opensbi/coverage_test/coverage_test_single_check_config.json --trace-log ./compare_result/statics_single.csv  --output cover_single.csv --addr2line /usr/bin/riscv64-linux-gnu-addr2line

```

For each test coverage.

```
./report/create_trace_report_by_each_test.sh single 10 0x80000000 ./configs/opensbi/coverage_test/coverage_test_single_check_config.json test_result_base_ecall_cover_test cov_report_each/single /usr/bin/riscv64-linux-gnu-addr2line

```

##### Multi coverage

For total coverage.

```
./tools/addr2line.py --base-addr 0x80000000 --config-json ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json --trace-log ./compare_result/statics_multi.csv --output cover_multi.csv --addr2line /usr/bin/riscv64-linux-gnu-addr2line
```

For each test coverage.

```
./report/create_trace_report_by_each_test.sh multi 10 0x80000000 ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json test_result_base_ecall_cover_test cov_report_each/multi /usr/bin/riscv64-linux-gnu-addr2line
``

#### Visualize coverage

For total coverage.

```
./report/create_coverage_result_html.py --single ./cover_single.csv --multi ./cover_multi.csv --html-dir html_output
```

For each test coverage.

```
./report/create_html_report_by_each_test.sh 10 ./cov_report_each/ each_html_report
```

#### Create ctags

```
ctags -R --languages=C --c-kinds=f --fields=+n -f tags.txt
```

