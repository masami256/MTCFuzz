from .optee_fuzzer import OpteeFuzzer

class OpteeXtest1001Fuzzer(OpteeFuzzer):
    def __init__(self, config: dict, task_id: int, ssh_client: "SSHClient", 
                 qmp_socket_path: str, serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client, qmp_socket_path, serial_socket_path0, serial_socket_path1, gdb_port)

    def generate_input(self, seed: dict, **kwargs) -> dict:
        mi = self.mutator.mutate(seed["input_len"]["value"])
        mb = self.mutator.mutate(seed["buffer_len"]["value"])
        return {
            "input_len": mi,
            "buffer_len": mb,
        }

    def run_test(self, fuzz_data: dict) -> dict:
        with open(self.fuzz_input_file, "w") as f:
            input_len = hex(fuzz_data["input_len"])
            buffer_len = hex(fuzz_data["buffer_len"])   
            f.write(f"{input_len},{buffer_len}")

        args = [
            "xtest",
            "-t", "fuzz",
            self.xtest_number,
        ]

        args_str = " ".join(args)
        return self.ssh_client.exec_command(args_str, retry_max=1)
