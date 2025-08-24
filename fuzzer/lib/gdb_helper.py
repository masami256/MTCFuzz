import os
import subprocess
import signal
import json
class GDBHelper:
    def __init__(self, config: dict, gdb_port: int, task_id: str, local_work_dir: str) -> None:
        self.gdb_path = config["fuzzing"].get("gdb_path", "/usr/bin/gdb-multiarch")
        self.task_id = task_id
        self.gdb_port = gdb_port

        self.target_binary = config["fuzzing"]["target_binary"]

        self.gdb_script_template = config["fuzzing"]["gdb_script_template"]
        self.gdb_script =  f"{local_work_dir}/fuzz_gdb_{task_id}.gdb"

        self.mutator_script_template = config["fuzzing"]["mutator_script_template"]
        self.mutator_data_file = f"{local_work_dir}/mutator_data_{task_id}.txt"
        self.mutator_script = f"{local_work_dir}/mutator_{task_id}.py"

        self.gdb_log_file = f"{local_work_dir}/gdb_{task_id}.log"

        self.target_address = config["fuzzing"]["target_address"]

        self.pid = None

        self.create_gdb_scripts()

    def create_gdb_scripts(self) -> None:
        self.create_mutator_script()
        self.create_gdb_script()

    def create_mutator_script(self) -> None:
        with open(self.mutator_script_template, 'r') as f:
            content = f.read()
            
            content = content.replace("__TARGET_ADDRESS__", str(self.target_address))
            content = content.replace("__DATA_FILE__", str(self.mutator_data_file))


        with open(self.mutator_script, 'w') as f:
            f.write(content)

    def create_gdb_script(self) -> None:
        with open(self.gdb_script_template, 'r') as template_file:
            content = template_file.read()
            
            content = content.replace("__LOG_FILE_NAME__", str(self.gdb_log_file))
            content = content.replace("__PORT__", str(self.gdb_port))
            content = content.replace("__MUTATOR_FILE__", str(self.mutator_script))

        with open(self.gdb_script, 'w') as f:
            f.write(content)

    def run_gdb(self) -> None:
        cmd = [
                self.gdb_path, 
                "-q",
                "-nx", 
                "-x", self.gdb_script,
                self.target_binary
            ]
        
        print(f"Running GDB with command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        self.pid = proc.pid
        print(f"GDB PID: {self.pid}")

    def terminate_gdb(self) -> None:
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                print(f"GDB with PID {self.pid} terminated.")
                self.pid = None
            except OSError as e:
                print(f"Error terminating GDB pid({self.pid}): {e}")
        else:
            print("GDB process not found.")

    def write_gdb_data_file(self, data: dict) -> None:
        with open(self.mutator_data_file, 'w') as f:
            json.dump(data, f, indent=4)
        # print(f"Data written to {self.mutator_data_file}")