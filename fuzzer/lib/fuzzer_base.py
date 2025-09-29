from .fuzzer_lib import *

class FuzzerBase:
    def __init__(self, config: dict, task_id: str, ssh_client: "SSHClient") -> None:
        self.config = config
        self.remote_work_dir = self.config["fuzzing"].get("remote_work_dir", "/root/work")
        self.local_work_dir = self.config["fuzzing"]["local_work_dir"]
        self.local_test_dir = None

        if self.config["fuzzing"].get("kernel_module") is not None:
            self.module_name = self.config["fuzzing"]["kernel_module"].split("/")[-1]
            self.remote_module_path = f"{self.remote_work_dir}/{self.module_name}"

        if self.config["fuzzing"].get("harness") is not None:
            self.harness_name = self.config["fuzzing"]["harness"].split("/")[-1]
            self.remote_harness_path = f"{self.remote_work_dir}/{self.harness_name}"

        self.ssh_client = ssh_client
        self.test_dir = None

        self.started = False
        self.machine_info_dir = f"{task_id}-{self.config['fuzzing'].get('machine_info_dir', 'machine_info')}"

    def wait_for_ready(self, *, timeout: int = 5) -> None:
        raise NotImplementedError("wait_for_ready() must be implemented in the subclass")

    async def initial_setup(self, local_work_dir: str, first_run: bool) -> None:
        raise NotImplementedError("initial_setup() must be implemented in the subclass")

    def prepare_harness(self) -> None:
        raise NotImplementedError("prepare_harness() must be implemented in the subclass")

    def copy_files(self) -> None:
        raise NotImplementedError("copy_files() must be implemented in the subclass")

    def extra_qemu_params(self) -> None:
        raise NotImplementedError("extra_qemu_params() must be implemented in the subclass")

    def create_remote_test_dir(self, test_dir: str) -> int:
        self.test_dir = f"{self.remote_work_dir}/{test_dir}"
        return self.ssh_client.exec_command(f"mkdir -p {self.test_dir}")

    def is_qemu_target(self) -> bool:
        return self.config.get("target_type") == "qemu"

    def send_module(self) -> int:
        return self.ssh_client.send_file(self.config["fuzzing"]["kernel_module"], f"{self.remote_module_path}")

    def send_harness(self) -> int:
        return self.ssh_client.send_file(self.config["fuzzing"]["harness"], f"{self.remote_harness_path}")

    def generate_input(self, seed: dict, **kwargs) -> dict:
        result = {}
        for key in seed:
            if seed[key]["fixed"]:
                result[key] = seed[key]["value"]
            else:
                if "mutaror" in seed[key] and seed[key]["mutator"] == "custom":
                    result[key] = self.mutator.custom_mutater(key, seed[key])
                elif seed[key]["type"] == "str":
                    result[key] = self.mutator.mutate_string(seed[key]["value"], seed[key]["min_len"], seed[key]["max_len"])
                else:
                    result[key] = self.mutator.mutate(seed[key]["value"])

        return result
