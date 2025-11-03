from ..qemu_fuzzer import QemuFuzzer
import logging
logger = logging.getLogger("mtcfuzz")

from typing import Any
import shutil
import os
from .optee_ftpm_tpm2_quote_mutator import OPTeeFtpmTpm2QuoteMutator
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

class OpteeFtpmTpm2QuoteFuzzer(QemuFuzzer):
    def __init__(self, config: dict, task_id: int, ssh_client: "SSHClient", 
                 qmp_socket_path: str, serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

        self.working_dir = self.local_work_dir + "/bin"

        self.hostshare_dir = self.local_work_dir + "/hostshare"
        os.makedirs(self.hostshare_dir, exist_ok=True)
        self.fuzz_input_file = self.hostshare_dir + "/fuzz_input.txt"

        self.remote_hostshare_dir = self.config["fuzzing"]["hostshare_9p"]
        self.fuzz_input_file_on_remote = f"{self.remote_hostshare_dir}/fuzz_input.txt"
    

        self.mutator = OPTeeFtpmTpm2QuoteMutator()

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
        
        exec_result = self.send_setup_scripts()
        if not exec_result == 0:
            logger.error(f"Failed to copy setup scripts")
            return False
        

        if not self.wait_for_tpmrm0_is_ready():
            return False

        logger.info(f"Setting up EK and AK")
        setup_script_file = os.path.basename(self.config["fuzzing"]["setup_scripts"][0])
        setup_script = f"{self.remote_work_dir}/{setup_script_file}"
        exec_result = self.ssh_client.exec_command(setup_script, remote_command_exec_timeout=30)
        if not exec_result["returncode"] == 0:
            logger.error(f"Failed to setup EK and AK")
            return False
        
        # logger.info(exec_result["stdout"])
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
    
    def write_tpm2_quote_test_parameters(self, fuzz_data: dict) -> None:
        target = fuzz_data["target"]
        size = fuzz_data["qualifyingData_size"]
        values = fuzz_data["qualifyingData_value"]

        with open(self.fuzz_input_file, "w") as f:  
            f.write(f"{target},{size},{values}")

        # copy seed file to test dir
        shutil.copy(self.fuzz_input_file, self.local_test_dir)

    def write_tpm2_invalid_sessions_test_parameters(self, fuzz_data: dict) -> None:
        target = fuzz_data["target"]
        tag = fuzz_data["invalid_sessions_tag"]
        values = fuzz_data["invalid_sessions_value"]
        size = len(values)

        with open(self.fuzz_input_file, "w") as f:  
            if size == 0:
                f.write(f"{target},{tag}\n")
            else:
                f.write(f"{target},{tag},{values}")

        # copy seed file to test dir
        shutil.copy(self.fuzz_input_file, self.local_test_dir)

    def run_test(self, fuzz_data: dict) -> dict:
        target = fuzz_data["target"]
        if target == "qualifyingData":
            self.write_tpm2_quote_test_parameters(fuzz_data)
        elif target == "invalid_sessions":
            self.write_tpm2_invalid_sessions_test_parameters(fuzz_data)

        args = [
            f"{self.remote_work_dir}/ftpm_fuzz",
            "--target", fuzz_data["fuzz_test_param_target"],
            "--in", self.fuzz_input_file_on_remote,
        ]

        args_str = " ".join(args)
        return self.ssh_client.exec_command(args_str, retry_max=1, remote_command_exec_timeout=5)
