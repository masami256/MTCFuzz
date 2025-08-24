from .sbi_fuzzer import SBIFuzzer
import shutil

class SBIEIDFuzzer(SBIFuzzer):
    def __init__(self, config: dict, task_id: int, ssh_client: "SSHClient", qmp_socket_path: str, 
                 serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

    def generate_input(self, seed: any, **kwargs):
        params = self.init_sbi_params()

        for reg in seed:
            d = seed[reg]
            if d["fixed"]:
                params[reg] = int(d["value"], 16)
            else:
                tmp = self.mutator.mutate(d["value"])
                if reg == "a7":
                    # prevent sending shutdown command
                    if tmp == 0x53525354 or tmp == 0x8:
                        while True:
                            d = seed[reg]
                            tmp = int(d["value"], 16)
                            if tmp != 0x53525354 and tmp != 0x8:
                                break

                params[reg] = tmp
                
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
