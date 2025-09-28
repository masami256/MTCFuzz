import logging
logger = logging.getLogger("mtcfuzz")

import subprocess
import time

from .ssh_error import SSHError

class SSHClient:
    def __init__(self, config: dict, qemu_ssh_port: int) -> None:
        self.config = config

        params = config.get("ssh_params", {})

        self.host = params.get("host", "localhost")
        self.port = qemu_ssh_port
        self.user = params.get("user", "root")
        self.identity = params.get("identity", None)
        
        self.ssh_retry_max = config["fuzzing"].get("ssh_retry_max", 5)
        self.remote_command_exec_timeout = config["fuzzing"].get("remote_command_exec_timeout", 2)

    def exec_command(self, cmd: str, *, retry_max: int = None) -> dict:
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-o", "UserKnownHostsFile=/dev/null",
        ]

        if self.identity:
            ssh_cmd += ["-i", self.identity]

        ssh_cmd += [
            "-p", str(self.port),
            f"{self.user}@{self.host}",
            cmd
        ]
        num_retries = retry_max if retry_max is not None else self.ssh_retry_max
        for attempt in range(num_retries):
            try:
                # logger.debug(f"Command: {ssh_cmd}")

                start = time.perf_counter()
                result = subprocess.run(
                    ssh_cmd,
                    # capture_output=False,
                    capture_output=True,
                    text=True,
                    timeout=self.remote_command_exec_timeout,
                )
                end = time.perf_counter()

                # Calculate elapsed time in microseconds
                elapsed_us = (end - start) * 1_000_000

                return {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "elapsed_us": elapsed_us,
                }

            except subprocess.TimeoutExpired as e:
                logger.warning(f"exec_command(): [SSH] Timeout executing command. Retry {attempt + 1}/{self.ssh_retry_max}...")
                logger.debug("=====================")
                logger.debug(e)
                logger.debug("=====================")
                time.sleep(attempt + 1)
            
            except Exception as e:
                logger.warning(f"exec_command(): [SSH] Error: {e}. Retry {attempt + 1}/{self.ssh_retry_max}...")
                time.sleep(attempt + 1)
        
        raise SSHError(f"exec_command(): Failed to execute command after {self.ssh_retry_max} attempts: {cmd}")

    def send_file(self, local_path: str, remote_path: str) -> int:
        scp_cmd = [
            "scp",
            "-O", # Use -O to enable OpenSSH compatibility mode
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
        ]

        if self.identity:
            scp_cmd += ["-i", self.identity]
        
        scp_cmd += [
            "-P", str(self.port),
            local_path,
            f"{self.user}@{self.host}:{remote_path}"
        ]  
        for attempt in range(self.ssh_retry_max):
            try:
                result = subprocess.run(
                    scp_cmd,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                return result.returncode
            except subprocess.TimeoutExpired:
                logger.warning(f"send_file(): [SCP] Timeout sending file. Retry {attempt + 1}/{self.ssh_retry_max}...")
                time.sleep(attempt + 1)
            except Exception as e:
                logger.warning(f"send_file(): [SCP] Error: {e}. Retry {attempt + 1}/{self.ssh_retry_max}...")
                time.sleep(attempt + 1)

        raise SSHError(f"send_file(): Failed to execute command after {self.ssh_retry_max} attempts")

    def copy_remote_files(self, remote_path: str, local_path: str) -> int:
        scp_cmd = [
            "scp",
            "-r",
            "-O", # Use -O to enable OpenSSH compatibility mode
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
        ]

        if self.identity:
            scp_cmd += ["-i", self.identity]

        scp_cmd += [
            "-P", str(self.port),
            f"{self.user}@{self.host}:{remote_path}",
            local_path
        ]

        # logger.debug(f"scp_cmd: {scp_cmd}")
        for attempt in range(self.ssh_retry_max):
            try:
                result = subprocess.run(
                    scp_cmd,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                return result.returncode
            except subprocess.TimeoutExpired:
                logger.warning(f"send_file(): [SCP] Timeout receiving file. Retry {attempt + 1}/{self.ssh_retry_max}...")
                time.sleep(attempt + 1)
            except Exception as e:
                logger.warning(f"send_file(): [SCP] Error: {e}. Retry {attempt + 1}/{self.ssh_retry_max}...")
                time.sleep(attempt + 1)

        raise SSHError(f"send_file(): Failed to execute command after {self.ssh_retry_max} attempts")

    def close(self) -> None:
        pass
