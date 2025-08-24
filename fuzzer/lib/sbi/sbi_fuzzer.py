from ..qemu_fuzzer import QemuFuzzer
from .sbi_mutator import SbiMutator

import shutil
import pprint

class SBIFuzzer(QemuFuzzer):
    def __init__(self, config: dict, task_id: int, ssh_client: "SSHClient", qmp_socket_path: str, 
                 serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

        self.mutator = SbiMutator()

    def extra_qemu_params(self) -> list[str]:
        return []
    
    def copy_files(self) -> bool:
        if "initrd" in self.config["qemu_params"]:
            copy_from_path = self.config['qemu_params']['initrd']
            copy_from_name = copy_from_path.split("/")[-1]
        elif "rootfs" in self.config["qemu_params"]:
            copy_from_path = self.config['qemu_params']['rootfs']
            copy_from_name = copy_from_path.split("/")[-1]
        else:
            print("Error: No initrd or rootfs specified in QEMU parameters.")
            return False
        
        copy_to = f"{self.local_work_dir}/{self.task_id}-{copy_from_name}"
        self.rootfs_file = copy_to
        shutil.copy(copy_from_path, copy_to)
    
        return True
    
    def prepare_harness(self) -> bool:
        exec_result = self.ssh_client.exec_command(f"mkdir -p {self.remote_work_dir}")
        if not exec_result["returncode"] == 0:
            print(f"Failed to create remote work directory: {self.remote_work_dir}")
            return False
        
        self.send_module()
        self.send_harness()

        exec_result = self.ssh_client.exec_command(f"insmod {self.remote_module_path}")
        if not exec_result["returncode"] == 0:
            print(f"Failed to insert module: {self.remote_module_path}")
            return False

        return True
    
    def init_sbi_params(self) -> dict:
        return  {
            "a0": 0x0,
            "a1": 0x0,
            "a2": 0x0,
            "a3": 0x0,
            "a4": 0x0,
            "a5": 0x0,
            "a6": 0x0,
            "a7": 0x0,
        }

    def generate_input(self, seed: any, **kwargs):
        params = self.init_sbi_params()

        for reg in seed:
            d = seed[reg]
            if d["fixed"]:
                params[reg] = int(d["value"], 16)
            else:
                params[reg] = self.mutator.mutate(d["value"])
                
        return params
    
    def run_test(self, fuzz_data: dict) -> dict:

        args = [
            f"{self.remote_harness_path}",
            f"-eid {fuzz_data['a7']:#x}",
            f"-fid {fuzz_data['a6']:#x}",
            f"-a0 {fuzz_data['a0']:#x}",
            f"-a1 {fuzz_data['a1']:#x}",
            f"-a2 {fuzz_data['a2']:#x}",
            f"-a3 {fuzz_data['a3']:#x}",
            f"-a4 {fuzz_data['a4']:#x}",
            f"-a5 {fuzz_data['a5']:#x}",
            f"-o {self.test_dir}",
        ]

        args_str = " ".join(args)

        # print(f"Running command: {args_str}")
        return self.ssh_client.exec_command(args_str, retry_max=1)
        
        # print(f"stdout: {stdout}")
        # print(f"stderr: {stderr}")
