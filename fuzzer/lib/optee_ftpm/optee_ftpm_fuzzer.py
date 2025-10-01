from ..qemu_fuzzer import QemuFuzzer
import logging
logger = logging.getLogger("mtcfuzz")

from typing import Any
import shutil
import os
from .optee_ftpm_mutator import OPTeeFtpmMutator
import time
import re
import pprint

ftpm_ta_uuid = "bc50d971-d4c9-42c4-82cb-343fb7f37896"
ftpm_load_pattern = re.compile(
    rf"D/LD:\s+ldelf:\d+\s+ELF\s+\({re.escape(ftpm_ta_uuid)}\)\s+at\s+(0x[0-9a-fA-F]+)"
)
ftpm_size_pattern = re.compile(
    rf"D/TC:\d+\s+\d+\s+early_ta_init:\d+\s+Early TA {re.escape(ftpm_ta_uuid)} size \d+ \(compressed, uncompressed (\d+)\)"
)

class OpteeFtpmFuzzer(QemuFuzzer):
    def __init__(self, config: dict, task_id: int, ssh_client: "SSHClient", 
                 qmp_socket_path: str, serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

        self.working_dir = self.local_work_dir + "/bin"

        self.hostshare_dir = self.local_work_dir + "/hostshare"
        os.makedirs(self.hostshare_dir, exist_ok=True)
        self.fuzz_input_file = self.hostshare_dir + "/fuzz_input.txt"

        self.remote_hostshare_dir = self.config["fuzzing"]["hostshare_9p"]
        self.fuzz_input_file_on_remote = f"{self.remote_hostshare_dir}/fuzz_input.txt"
    

        self.mutator = OPTeeFtpmMutator()

        #self.xtest_number = str(self.config["fuzzing"]["xtest_number"])
    def extra_qemu_params(self) -> list[str]:
        return [
            "-cpu", "max,sme=on,pauth-impdef=on",
            "-d", "unimp",
            "-semihosting-config", "enable=on,target=native",
            "-fsdev", f"local,id=fsdev0,path={self.hostshare_dir},security_model=none",
            "-device", "virtio-9p-device,fsdev=fsdev0,mount_tag=hostshare"
        ]

    def copy_files(self) -> bool:
        from_path = self.config["fuzzing"]["optee_artifact_dir"]
        to_path = self.working_dir

        shutil.copytree(from_path, to_path, symlinks=True)

        return True

    def create_qemu_params(self) -> list[str]:
        shutil.copy(self.config['qemu_params']['initrd'], self.qemu_rootfs)
        
        params = [
            self.config["qemu_params"]["qemu_path"],
            "-machine", "virt",
            "-bios",  self.config["qemu_params"]["bios"],
            "-kernel", self.config["qemu_params"]["kernel"],
            "-append", f'"{self.config["qemu_params"]["append"]}"',
            "-cpu", "max,sme=on,pauth-impdef=on"
        ]

        return params
    
    def prepare_harness(self) -> bool:
        args = [
            "mkdir", "-p",
            self.remote_hostshare_dir,
        ]

        args_str = " ".join(args)

        exec_result = self.ssh_client.exec_command(args_str, retry_max=1)
        if not exec_result["returncode"] == 0:
            logger.error(f"Failed to create remote 9p file system directory: {self.remote_hostshare_dir}")
            return False

        args = [
            "mount", "-t", "9p", 
            "-o", "trans=virtio", self.config["fuzzing"]["tag_9p"], 
            self.remote_hostshare_dir,
        ]

        args_str = " ".join(args)

        exec_result = self.ssh_client.exec_command(args_str, retry_max=1)
        if not exec_result["returncode"] == 0:
            logger.error(f"Failed to mount 9p file system: {self.remote_work_dir}")
            return False

        exec_result = self.ssh_client.exec_command(f"mkdir -p {self.remote_work_dir}")
        if not exec_result["returncode"] == 0:
            logger.error(f"Failed to create remote work directory: {self.remote_work_dir}")
            return False
        
        exec_result = self.send_harness()
        if not exec_result == 0:
            logger.error(f"Failed to copy test harness")
            return False
        
        if not self.wait_for_tpmrm0_is_ready():
            return False

        return True

    def wait_for_tpmrm0_is_ready(self) -> bool:
        args = [
            "ls", "/dev/tpmrm0"
        ]
        args_str = " ".join(args)

        for i in range(10):
            exec_result = self.ssh_client.exec_command(args_str)
            if exec_result["returncode"] == 0:
                return True
            time.sleep(1)
            
        return False
    
    def write_nvwrite_test_parameters(self, fuzz_data: dict) -> None:
        flags0 = fuzz_data['flags0'] if type(fuzz_data['flags0']) == str else hex(fuzz_data['flags0'])
        flags1 = fuzz_data['flags1'] if type(fuzz_data['flags1']) == str else hex(fuzz_data['flags1'])
        declared_size_delta = fuzz_data['declared_size_delta'] if type(fuzz_data['declared_size_delta']) == str else hex(fuzz_data['declared_size_delta'])
        offset_delta = fuzz_data['offset_delta'] if type(fuzz_data['offset_delta']) == str else hex(fuzz_data['offset_delta'])
        authsize_delta = fuzz_data['authsize_delta'] if type(fuzz_data['authsize_delta']) == str else hex(fuzz_data['flags0'])
        swap_handles = fuzz_data['swap_handles'] if type(fuzz_data['swap_handles']) == str else hex(fuzz_data['swap_handles'])
        payload_len = fuzz_data['payload_len'] if type(fuzz_data['payload_len']) == str else hex(fuzz_data['payload_len'])

        with open(self.fuzz_input_file, "w") as f:  
            f.write(f"{flags0}\n")
            f.write(f"{flags1}\n")
            f.write(f"{declared_size_delta}\n")
            f.write(f"{offset_delta}\n")
            f.write(f"{authsize_delta}\n")
            f.write(f"{swap_handles}\n")
            f.write(f"{payload_len}\n")
            f.write(f"{fuzz_data['payload']}\n")

        # copy seed file to test dir
        shutil.copy(self.fuzz_input_file, self.local_test_dir)

    def extra_setup(self, coverage: Any):

        console1_log = f"{self.local_work_dir}/{self.task_id}-console1.log"
        with open(console1_log) as f:
            log = f.read()

        ta_size = None
        ta_address = None

        match = ftpm_load_pattern.search(log)
        if match:
            ta_address = match.group(1)
            if ta_address is None:
                logger.info(f"{ftpm_ta_uuid} loaded address is not determined")
                return
            ta_address = int(ta_address, 16)
        else:
            logger.info(f"{ftpm_ta_uuid} loaded address is not determined")
            return

        match = ftpm_size_pattern.search(log)
        if match:
            ta_size = match.group(1)
            if ta_size is None:
                logger.info(f"{ftpm_ta_uuid} size is not determined")
                return
        else:
            logger.info(f"{ftpm_ta_uuid} size is not determined")
            return

        orig_size = int(ta_size, 16)
        aligned_size = (orig_size + 4095) & ~4095
        logger.info(f"fTPM TA({ftpm_ta_uuid}) is located at {hex(ta_address)}. size is {hex(orig_size)} : aligned size: {hex(aligned_size)}")

        orig_filter = coverage.get_firmware_filter()
        end_address = hex(ta_address + aligned_size)
        start_address = hex(ta_address)


        new_filter = {
            'lower': start_address,
            'upper': end_address
        }

        orig_filter.append(new_filter)
        coverage.update_firmware_filter(orig_filter)

    def run_test(self, fuzz_data: dict) -> dict:
        self.write_nvwrite_test_parameters(fuzz_data)
        args = [
            f"{self.remote_work_dir}/ftpm_fuzz",
            "--target", "nvwrite",
            "--in", self.fuzz_input_file_on_remote,
        ]

        args_str = " ".join(args)
        return self.ssh_client.exec_command(args_str, retry_max=1, remote_command_exec_timeout=5)
