#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
logging.basicConfig(level = logging.INFO, format='%(asctime)s:%(levelname)s: %(message)s')
logger = logging.getLogger("mtcfuzz")

import argparse
import json
import traceback
import os
import asyncio
import uuid
import signal
from datetime import datetime

from lib.fuzzer_factory import fuzzer_factory
from lib.coverage_factory import coverage_factory
from lib.seed_manager_factory import seed_manager_factory
from lib.ssh_client import SSHClient
import lib.fuzzer_lib as fuzzer_lib
from lib.ssh_error import SSHError
from lib.serial import Serial
from lib.qemu_tracer import QemuTracer
from lib.coverage_manager import CoverageManager
from lib.gdb_helper import GDBHelper
from lib.powerscheduler import PowerScheduler
from lib.crashed_testcase_manager import CrashedTestcaseManager

import pprint

def read_config(config_path):
    """
    Read the configuration file and return the configuration dictionary.
    """
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_path} not found.")
        return None
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from the configuration file {config_path}.")
        return None

def is_pid_exist(pid):
    """
    Check if a process with the given PID exists.
    """
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def is_crashed(console0_log, console1_log):
    if fuzzer_lib.is_crashed(console0_log):
        return True
    
    if console1_log:
        if fuzzer_lib.is_crashed(console1_log):
            return True
    return False

def parser_argument():
    parser = argparse.ArgumentParser(description="Fuzzer for SBI")
    parser.add_argument("-c", "--config", type=str, default="config.json", help="Path to the configuration file")

    return parser.parse_args()

def save_config(config: dict, local_work_dir: str) -> None:
    filename = f"{local_work_dir}/updated-config.json"
    with open(filename, "w") as f:
        json.dump(config, f, indent=4)

async def start_fuzzing(config, task_num, crashedTestcaseManager):
    tracing = False
    snapshot_created = False
    pid = None

    task_id = f"task-{task_num}"
    local_work_dir = config["fuzzing"]["local_work_dir"]

    file_handler = logging.FileHandler(f"{local_work_dir}/mtcfuzz-{task_id}.log", mode="a", encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s: %(message)s"))
    logger.addHandler(file_handler)

    qemu_ssh_port = config["qemu_params"].get("port", 10022) + task_num
    gdb_port =  config["fuzzing"].get("gdb_port", 1234) + task_num
    use_gdb = config["fuzzing"].get("use_gdb", False)
    gdb = None
    qemu_wait_sec = config["fuzzing"]["wait_for_qemu_seconds"]
    max_fuzzing_loop = config["fuzzing"].get("max_fuzzing_loop", 1000)

    default_energy = config["fuzzing"].get("default_energy", 100)
    ps = PowerScheduler(config["fuzzing"]["assign_energy_function"], M = default_energy)

    total_elapsed_us = 0
    total_tested_count = 0

    try:
        coverManager = CoverageManager()

        Coverage = coverage_factory(config)
        coverage = Coverage(config)

        seed_dir = config["fuzzing"]["seed_dir"]
        SeedManager = seed_manager_factory(config)
        seedManager = SeedManager(seed_dir, task_id)

        
        if not os.path.exists(local_work_dir):
            os.makedirs(local_work_dir)

        qmp_socket_path = f"{local_work_dir}/qemu_fuzzer_{task_id}_qmp.sock"
        serial_socket_path0 = f"{local_work_dir}/qemu_fuzzer_{task_id}_serial0.sock"
        serial_socket_path1 = None
        has_extra_serial = config["qemu_params"].get("extra_serial", False)
        if has_extra_serial:
            serial_socket_path1 = f"{local_work_dir}/qemu_fuzzer_{task_id}_serial1.sock"
        
        main_serial = None
        extra_serial = None

        if use_gdb:
            gdb = GDBHelper(config, gdb_port, task_id, local_work_dir)

        qt = QemuTracer(task_id, qmp_socket_path)

        loop_cnt = 0
        fuzzing_done = False

        ssh_client = SSHClient(config, qemu_ssh_port)
        
        Fuzzer = fuzzer_factory(config)
        if Fuzzer is None:
            logger.error("Failed to get fuzzer.")
            return
        fuzzer = Fuzzer(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

        machine_info_dir = f"{local_work_dir}/{fuzzer.machine_info_dir}"
        if not os.path.exists(machine_info_dir):
            os.makedirs(machine_info_dir)

        ret = fuzzer.start_machine()
        if not ret:
            logger.error("Failed to launch machine.")
            return

        if use_gdb:
            gdb.run_gdb()

        fuzzer.wait_for_ready(timeout=qemu_wait_sec)

        ret, pid = await fuzzer.initial_setup(local_work_dir, True)
        if not ret:
            return -1
        
        fuzzer.extra_setup(coverage)

        save_config(config, local_work_dir)
        exit(0)
        # main fuzzing loop start
        while not fuzzing_done:
            if loop_cnt > max_fuzzing_loop:
                fuzzing_done = True
                break
            if fuzzing_done:
                break

            seed = seedManager.get_random_seed()

            seed_id = seed["id"]
            coverManager.count_other_seeds_with_same_coverage(seed["coverage_hash"], seed_id)
            energy = ps.assign_energy(seed, total_tested_count, total_elapsed_us)
            logger.info(f"Loop {loop_cnt}, Seed ID: {seed_id}, Energy: {energy}")
            # seed loop start
            fuzz_i = 0
            while True:
                logger.info("===========================")
                need_restart = False
                if fuzz_i > energy:
                    logger.info("Energy exhausted, moving to next seed.")
                    break
                try:
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    uuid_str = f"{timestamp}-{str(uuid.uuid4())}"
                    test_dir_name = f"{task_id}-{uuid_str}"
                    local_test_dir = f"{local_work_dir}/{test_dir_name}"
                    fuzzer.local_test_dir = local_test_dir

                    logger.info(f"Test: {test_dir_name}")
                    console0_log = f"{local_test_dir}/console0.log"
                    console1_log = None

                    # setup work dir
                    
                    fuzzer.create_remote_test_dir(test_dir_name)
                    os.makedirs(local_test_dir)
                    
                    if not snapshot_created:
                        ret = await fuzzer.save_state()
                        if not ret:
                            logger.error("Failed to save state.")
                            return -1
                        snapshot_created = True

                    trace_log = f"{local_test_dir}/qemu_trace_log.log"
                    fuzz_params = fuzzer.generate_input(seed["seed"])

                    if use_gdb:
                        gdb.write_gdb_data_file(fuzz_params)
                    
                    elapsed_us = 0
                    main_serial = Serial(serial_socket_path0, console0_log)
                    main_serial.open()

                    if has_extra_serial:
                        console1_log = f"{local_test_dir}/console1.log"
                        extra_serial = Serial(serial_socket_path1, console1_log)
                        extra_serial.open()
                    
                    # pprint.pprint(f"test: {test_no}, params: {fuzz_params}")
                    await qt.tracer_on(trace_log)
                    tracing = True
                    
                    exec_result = None
                    maybe_crashed = False

                    try:
                        exec_result = fuzzer.run_test(fuzz_params)
                    except SSHError as e:
                        logger.info("Maybe got a crash")
                        maybe_crashed = True
                        need_restart = True

                    if not maybe_crashed:
                        # We don't have to off the qmp command because we should reboot qemu
                        await qt.tracer_off()

                    tracing = False
                    main_serial.read()
                    main_serial.close()

                    if has_extra_serial:
                        extra_serial.read()
                        extra_serial.close()    

                    total_tested_count += 1

                    if exec_result:
                        elapsed_us = exec_result["elapsed_us"]
                        total_elapsed_us += elapsed_us

                        with open(f"{local_test_dir}/stdout.txt", "w") as f:
                            f.write(exec_result["stdout"])
                        with open(f"{local_test_dir}/stderr.txt", "w") as f:
                            f.write(exec_result["stderr"])
                            
                    if maybe_crashed or is_crashed(console0_log, console1_log):
                        logger.info(f"[+]Found crash! : Test dir: {local_test_dir}")
                        await crashedTestcaseManager.add_crashed_testcase(fuzz_params)
                        crashedTestcaseManager.save_params(local_test_dir, fuzz_params)
                    else:
                        exec_result = ssh_client.exec_command("dmesg -c")
                        fuzzer_lib.save_cmd_output(exec_result["stdout"], f"{local_test_dir}/dmesg.log")

                        ssh_client.copy_remote_files(fuzzer.test_dir, local_work_dir)
                        cover_pcs = coverage.read_coverage(trace_log)
                        kcov_found, fcov_found, trace_hash = coverage.analyze_coverage(cover_pcs)
                        if kcov_found or fcov_found:
                            seedManager.add_seed(seed_id, fuzz_params, elapsed_us, coverage.get_coverages())
                        else:
                            seedManager.update_seed(seed, elapsed_us)
                            
                        coverManager.merge_coverage(coverage.get_coverages())

                        total_same_coverage_count = coverManager.count_other_seeds_with_same_coverage(trace_hash, seed_id)
                        seedManager.update_coverage_hash(seed_id, trace_hash, total_same_coverage_count)

                        logger.info(f"kernel coverage: {kcov_found}, firmware coverage: {fcov_found}")

                except KeyboardInterrupt:
                    logger.info("Ctrl-C detected, finish fuzzing loop...")
                    fuzzing_done = True
                except Exception as e:
                    logger.error(f"An error occurred: {e}")
                    traceback.print_exc()
                    fuzzing_done = True
                finally:
                    fuzz_i += 1

                    if main_serial:
                        main_serial.close()
                        main_serial = None
                    if extra_serial:
                        extra_serial.close()
                        extra_serial = None
                    
                    if tracing:
                        await qt.tracer_off()
                    tracing = False

                    if not fuzzing_done:
                        if need_restart or not is_pid_exist(pid):
                            if is_pid_exist(pid):
                                logger.info(f"Stop qemu pid: {pid}")
                                fuzzer.stop_machine()
                            
                            logger.info("Restarting machine...")
                            ret = fuzzer.start_machine()
                            if not ret:
                                logger.info("Failed to launch machine.")
                                return
                            fuzzer.wait_for_ready(timeout=qemu_wait_sec)

                            ret, pid = await fuzzer.initial_setup(local_work_dir, False)
                            if not ret:
                                logger.info("Failed to restart machine.")
                                break

                            snapshot_created = False
                            logger.info(f"Restarted machine with PID: {pid}")

                        elif fuzzer:
                            logger.info("Restoring machine state...")
                            ret = await fuzzer.loadvm()

                    else:
                        logger.info("Fuzzing done, cleaning up...")
                        await fuzzer.delvm()
                        
                        fuzzer.stop_machine()
                        break     
            # end of seed loop
            loop_cnt += 1
        # end of main fuzzing loop
    except KeyboardInterrupt:
        logger.info("Ctrl-C detected, finish fuzzing...")
    except Exception as e:
        logger.info(f"An error occurred in the main loop: {e}")
        traceback.print_exc()
    except asyncio.CancelledError:
        logger.info("Fuzzing cancelled by user.")
    finally:
        logger.info(f"check pid {pid}")
        if pid and is_pid_exist(pid):
            logger.info(f"Process with PID {pid} is still running. Terminating...")
            os.kill(pid, signal.SIGTERM)
        
        if gdb:
            gdb.terminate_gdb()

async def main():
    args = parser_argument()

    config = read_config(args.config)
    if config is None:
        return

    crashedTestcaseManager = CrashedTestcaseManager()

    num_fuzzers = config["fuzzing"].get("num_fuzzers", 1)
    try:
        tasks = [
            asyncio.create_task(start_fuzzing(config, i, crashedTestcaseManager))
            for i in range(num_fuzzers)
        ]
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("Ctrl-C detected, cancelling tasks...")
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("All tasks cancelled.")
    except asyncio.CancelledError:
        logger.info("Fuzzing cancelled by user.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Ctrl-C detected, cancelling tasks...")