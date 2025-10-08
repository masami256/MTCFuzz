# OP-TEE xtest fuzz 1000 test

## Run

Run the test by executing tests/run-fuzz.sh, which runs fuzzer/main.py.

#### Run single coverage trace test.

```
./tests/run-fuzz.sh ./configs/optee/ftpm_fuzz/ftpm_nv_write_single_config.json ./test_results/single 5m 10
```

#### Run multi coverage trace test.

```
./tests/run-fuzz.sh ./configs/optee/ftpm_fuzz/ftpm_nv_write_multi_config.json ./test_results/multi 5m 10
```

#### Collect single and multi fuzzing result

##### Collect single trace coverages

```
./report/create-coverage-report.sh ./configs/optee/ftpm_fuzz/ftpm_nv_write_single_config.json test_results/single/
```

##### Collect multi trace coverages

```
./report/create-coverage-report.sh ./configs/optee/ftpm_fuzz/ftpm_nv_write_multi_config.json test_results/multi/
```

#### Create total report

Run report/compare_test_results.py to collect logs.

```
./report/compare_test_results.py --single ./test_results/single/ --multi ./test_results/multi/ --output-dir ./test_results/compare_results
```

### Analyze

#### Run addr2line to get source code information

Run tools/addr2line.py to get source code information.

##### Single coverage

```
./tools/addr2line.py --config ./tests/optee/ftpm/optee_ftpm_trace_config.yml --trace-log ./test_results/compare_results/statics_single.csv --output test_results/a2r_single.csv
```

##### Multi coverage

```
./tools/addr2line.py --config ./tests/optee/ftpm/optee_ftpm_trace_config.yml --trace-log ./test_results/compare_results/statics_multi.csv --output test_results/a2r_multi.csv
```

#### Visualize coverage

For total coverage.

```
./report/create_coverage_result_html.py --single ./test_results/a2r_single.csv --multi ./test_results/a2r_multi.csv --html-dir ./test_results/html_output
```


