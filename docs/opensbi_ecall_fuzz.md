# OpenSBI ecall test

# OP-TEE xtest fuzz 1000 test

## Run

Run the test by executing tests/run-fuzz.sh, which runs fuzzer/main.py.

#### Run single coverage trace test.

```
./tests/run-fuzz.sh ./configs/opensbi/coverage_test/coverage_test_single_check_config.json ./test_results/single 5m 10
```

#### Run multi coverage trace test.

```
./tests/run-fuzz.sh ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json ./test_results/multi 5m 10
```

#### Collect single and multi fuzzing result

##### Collect single trace coverages

```
./report/create-coverage-report.sh ./configs/opensbi/coverage_test/coverage_test_single_check_config.json test_results/single/
```

##### Collect multi trace coverages

```
./report/create-coverage-report.sh ./configs/opensbi/coverage_test/coverage_test_multi_check_config.json test_results/multi/
```

#### Create total report

Run report/compare_test_results.py to collect logs.

```
./report/compare_test_results.py --single ./test_results/single/ --multi ./test_results/multi/ --output-dir ./test_results/compare_results
```

#### Create each test report

Run report/compare_test_results_by_each_test.sh to collect logs.

```
./report/compare_test_results_by_each_test.sh test_results/multi/ test_results/single/ 50 test_results/compare_each
```

### Analyze

#### Run addr2line to get source code information

Run tools/addr2line.py to get source code information.

##### Single coverage

```
./tools/addr2line.py --config ./tests/opensbi/base_ecall_coverage_test/opensbi_base_ecall_trace_config.yml --trace-log ./test_results/compare_results/statics_single.csv --output test_results/a2r_single.csv
```

##### Multi coverage

```
./tools/addr2line.py --config ./tests/opensbi/base_ecall_coverage_test/opensbi_base_ecall_trace_config.yml --trace-log ./test_results/compare_results/statics_multi.csv --output test_results/a2r_multi.csv
```

#### Run addr2line to get source code information for each tests

Run report/run_addr2line_by_each_test.sh to get source code information.

##### Get coverage

```
./report/run_addr2line_by_each_test.sh tests/opensbi/base_ecall_coverage_test/opensbi_base_ecall_trace_config.yml ./test_results/compare_each/ 50
```


#### Visualize coverage

For total coverage.

```
./report/create_coverage_result_html.py --single ./test_results/a2r_single.csv --multi ./test_results/a2r_multi.csv --html-dir ./test_results/html_output
```

For each coverage.

```
./report/create_coverage_result_html_by_each_test.sh ./test_results/compare_each/ 50
```