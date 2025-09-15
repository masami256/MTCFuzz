from ..qemu_fuzzer import QemuFuzzer

import shutil
import os
from .optee_mutator import OPTeeMutator
import pprint

class OpteeFuzzer(QemuFuzzer):
    def __init__(self, config: dict, task_id: int, ssh_client: "SSHClient", 
                 qmp_socket_path: str, serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

        self.working_dir = self.local_work_dir + "/bin"

        self.hostshare_dir = self.local_work_dir + "/hostshare"
        os.makedirs(self.hostshare_dir, exist_ok=True)

        self.remote_hostshare_dir = self.config["fuzzing"]["hostshare_9p"]
        self.fuzz_input_file = self.hostshare_dir + "/fuzz_input.txt"

        self.mutator = OPTeeMutator()

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

        self.ssh_client.exec_command(args_str, retry_max=1)
        args = [
            "mount", "-t", "9p", 
            "-o", "trans=virtio", self.config["fuzzing"]["tag_9p"], 
            self.remote_hostshare_dir,
        ]

        args_str = " ".join(args)

        self.ssh_client.exec_command(args_str, retry_max=1)

        return True

    def write_xtest_parameters(self, fuzz_data: dict) -> None:
        arr = []
        for key in fuzz_data:
            if not key == "xtest_number":
                arr.append(str(fuzz_data[key]))

        data = ",".join(arr)
        with open(self.fuzz_input_file, "w") as f:  
            f.write(data)

    def run_test(self, fuzz_data: dict) -> dict:
        self.write_xtest_parameters(fuzz_data)
        args = [
            "xtest",
            "-t", "fuzz",
            str(fuzz_data["xtest_number"]),
        ]

        args_str = " ".join(args)
        return self.ssh_client.exec_command(args_str, retry_max=1)
