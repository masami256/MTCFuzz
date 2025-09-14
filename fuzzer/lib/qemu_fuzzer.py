import logging
logger = logging.getLogger("mtcfuzz")

import os

from .fuzzer_base import FuzzerBase
from .fuzzer_lib import *

import subprocess
import signal
import os
import time
import random
import string
import traceback

from qemu.qmp import QMPClient

class QemuFuzzer(FuzzerBase):
    def __init__(self, config: dict, task_id: str, ssh_client, qmp_socket_path: str, 
                 serial_socket_path0: str, serial_socket_path1: str, gdb_port: int) -> None:
        super().__init__(config, task_id, ssh_client)
        self.qemu_process = None
        self.task_id = task_id
        self.snapshot_name = "mtcfuzz_vm_snapshot"
        self.qmp_socket_path = qmp_socket_path
        self.serial_socket_path0 = serial_socket_path0
        self.serial_socket_path1 = serial_socket_path1
        self.snapshot_created_file = f"{config["fuzzing"]["local_work_dir"]}/{task_id}-snapshot_created.txt"
        self.qmp_client_name = "mtcfuzz-qmp-client"
        self.rootfs_device_name = None
        self.rootfs_file = None
        self.snapshot_device_name = "snapshot0"
        self.qemu_host = self.config['qemu_params'].get("host", "10.0.2.2")
        self.node_name = None
        self.qmp = None
        self.qemu_pid = None
        self.qemu_snapshot_storage = f"{self.local_work_dir}/fuzz-snapshot.qcow2"
        self.qemu_snapshot_storage_size = config["fuzzing"].get("qemu_snapshot_storage_size", "4G")
        self.qemu_ssh_local_port = self.ssh_client.port
        self.gdb_port = gdb_port
        self.use_gdb = config["fuzzing"].get("use_gdb", False)
        self.working_dir = None
        self.first_boot = True

    def create_snapshot_storage(self) -> bool:
        if not os.path.exists(self.qemu_snapshot_storage):
            cmd = ["qemu-img", "create", "-f", "qcow2", self.qemu_snapshot_storage, self.qemu_snapshot_storage_size]

            try:
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                return True
            except Exception as e:
                logger.error(f"Failed to create snapshot storage: {e}")
                return False
        else:
            logger.info("QEMU snapshot file exists")
            return False
    
    def start_machine(self) -> bool:
        if self.started:
            logger.warning("Machine already started, skipping startup.")
            return True
        
        if not self.create_snapshot_storage():
            logger.warning("Create snapshot failed")
            return False
    
        params = [
            self.config["qemu_params"]["qemu_path"],
            "-machine", self.config["qemu_params"]["machine"],
            "-bios",  self.config["qemu_params"]["bios"],
            "-kernel", self.config["qemu_params"]["kernel"],
            "-append", f'"{self.config["qemu_params"]["append"]}"',
            "-nographic",
            # snapshot parameters
            "-drive", f"file={self.qemu_snapshot_storage},if=none,format=qcow2,id={self.snapshot_device_name}",
            # network parameters
            "-netdev", f"user,id=net0,host={self.qemu_host},hostfwd=tcp::{self.qemu_ssh_local_port}-:22",
            "-device", "virtio-net-device,netdev=net0",
            # cpu and memory parameters
            "-smp", self.config["qemu_params"].get("smp", "1"),
            "-m", self.config["qemu_params"].get("memory", "1024"),
            # qmp and serial parameters
            "-qmp", f"unix:{self.qmp_socket_path},server,nowait",
            "-serial", f"unix:{self.serial_socket_path0},server,nowait",
            # rng parameters
            "-object", "rng-random,filename=/dev/urandom,id=rng0",
            "-device", "virtio-rng-device,rng=rng0",
        ]

        if self.serial_socket_path1:
            params += ["-serial", f"unix:{self.serial_socket_path1},server,nowait"]

        if "initrd" in self.config["qemu_params"]:
            params += ["-initrd", self.config["qemu_params"]["initrd"]]

        params += self.extra_qemu_params()

        if self.first_boot:
            self.copy_files()
            self.first_boot = False

        if "rootfs" in self.config["qemu_params"]:
            self.rootfs_device_name = "rootfs0"
            params += ["-drive", f"file={self.rootfs_file},if=none,format=qcow2,id={self.rootfs_device_name}"]
            params += ["-device", f"virtio-blk-device,drive={self.rootfs_device_name}"]
        
        if self.use_gdb:
            params.append("-gdb", f"tcp::{self.gdb_port}")
            params.append("-S")
        
        stdout_output_to = subprocess.DEVNULL if not self.config["debug"] else None
        stderr_outpto_to = subprocess.DEVNULL if not self.config["debug"] else None

        if self.config["debug"]:
            output_to = subprocess.PIPE

        logger.info(f"Launching QEMU with command: \n{' '.join(params)}\n")

        if self.working_dir:
            logger.debug(f"Working directory: {self.working_dir}")
        try:
            process = subprocess.Popen(params, stdout=stdout_output_to, stderr=stderr_outpto_to, shell=False, cwd=self.working_dir)
        except Exception as e:
            logger.error(f"Error launching QEMU: {e}")
            return False

        self.qemu_process = process
        self.qemu_pid = self.qemu_process.pid
        logger.info(f"QEMU launched with PID: {self.get_pid()}")

        self.started = True
        return True

    async def initial_setup(self, local_work_dir: str, first_run: bool) -> tuple[bool, int]:
        try:
            self.prepare_harness()

            if first_run:
                self.create_remote_test_dir(self.machine_info_dir)

                local_initial_workdir = f"{local_work_dir}/{self.machine_info_dir}"
                if not os.path.exists(local_initial_workdir):
                    os.makedirs(local_initial_workdir)
                
                exec_result = self.ssh_client.exec_command("dmesg -c")
                save_cmd_output(exec_result["stdout"], f"{local_initial_workdir}/boot-dmesg.log")
            
                self.ssh_client.exec_command("sysctl -w kernel.randomize_va_space=0")
                save_cmd_output(exec_result["stdout"], f"{local_initial_workdir}/disable_aslr.log")

            pid = self.get_pid()
            logger.info(f"Process with PID {pid} is running.")
            return True, pid
        
        except Exception as e:
            logger.error(f"Error during initial setup: {e}")
            traceback.print_exc()
            return False, -1
    
    async def save_state(self) -> bool:
        self.ssh_client.exec_command("sync")
        ret = await self.savevm()
        return ret
    
    def get_pid(self) -> int:
        return self.qemu_pid

    def wait_for_ready(self, *, timeout: float = 5):
        wait_time = timeout
        if self.snapshot_created():
            wait_time = 0.1
        
        logger.info(f"Waiting for {wait_time} seconds for QEMU to be ready...")
        time.sleep(wait_time)

    def stop_machine(self) -> None:
        if self.qemu_process is None:
            return

        self.qemu_process.send_signal(signal.SIGKILL)
        ret = self.qemu_process.wait(timeout=2)
        logger.info(f"Process exited with code: {ret}")

        if self.qemu_process.poll is None:
            self.qemu_process.send_signal(signal.SIGKILL)
            ret = self.qemu_process.wait(timeout=2)
            logger.info(f"Process exited with code: {ret}")

        # subprocess.run("pkill -kill $(pgrep qemu-system)", shell=True)

        self.remove_snapshot()
        self.started = False
        self.qemu_process = None

    def generate_snapshot_job_id(self, prefix: str) -> str:
        length = 32
        chars = string.ascii_letters + string.digits
        random_part = ''.join(random.choices(chars, k=length))
        return f"mtcfuzz-snapshot-{prefix}-{random_part}"

    async def connect_qmp(self) -> bool:
        if self.qmp is None:
            self.qmp = QMPClient(self.qmp_client_name)

            try:
                await self.qmp.connect(self.qmp_socket_path)
                return True
            except Exception as e:
                logger.error(f"connect_qmp(): Error connecting to QMP: {e}")
                return False
        # If already connected, return True
        return True
    
    async def disconnect_qmp(self) -> None:
        try:
            if self.qmp is not None:
                await self.qmp.disconnect()
        except Exception as e:
            logger.error(f"Error disconnecting QMP: {e}")
            pass
        finally:
            self.qmp = None

    async def find_block_device(self) -> str | None:
        ret = await self.connect_qmp()
        if not ret:
            return None
        
        # TODO: do we need to check the status?
        #res = await self.qmp.execute('query-status')

        node_name = None
        try:
            res = await self.qmp.execute('query-block')

            for dev in res:
                # logger.debug(f"Block device: {dev['device']}")
                if dev["device"] == self.snapshot_device_name:
                    node_name = dev["inserted"]["node-name"]
            
            if node_name is None:
                logger.error("Error: node-name not found")
                return None
            
            return node_name
        
        except Exception as e:
            logger.error(f"find_block_device Error: {e}")
            raise(e)
    
    async def stopvm(self) -> None:
        await self.qmp.execute("stop")

    async def contvm(self) -> None:
        await self.qmp.execute("cont")

    async def savevm(self) -> bool:
        
        ret = False
        try:
            await self.connect_qmp()
            if self.node_name is None:
                self.node_name = await self.find_block_device()

            if self.node_name is None:
                logger.error("Error: node_name is None, cannot save snapshot")
                return False
            
            await self.stopvm()

            devices = [self.node_name]
            if self.rootfs_device_name is not None:
                devices.append(self.rootfs_device_name)

            args = {
                "job-id": self.generate_snapshot_job_id("save"), 
                "tag": "mtcfuzz-snapshot", 
                "vmstate": self.node_name, 
                "devices": devices,
            }

            logger.info("saving snapshot...")

            res = await self.qmp.execute("snapshot-save", args)

            with open(self.snapshot_created_file, "w") as f:
                f.write("snapshot created")

            logger.info(f"Snapshot was created successfully: {self.snapshot_created_file}")

            await self.contvm()
            ret = True
        except Exception as e:
            logger.error(f"savevm() Error: {e}")
            traceback.print_exc()
        finally:
            await self.disconnect_qmp()
            return ret

    async def loadvm(self) -> bool:
        ret = False

        try:
            ret = await self.connect_qmp()
            if not ret:
                return False
            
            if self.node_name is None:
                self.node_name = await self.find_block_device()
            
            await self.stopvm()

            args = {
                "job-id": self.generate_snapshot_job_id("load"), 
                "tag": "mtcfuzz-snapshot", 
                "vmstate": self.node_name, 
                "devices": [f"{self.node_name}"],
            }

            res = await self.qmp.execute("snapshot-load", args)

            await self.contvm()
            ret = True
        except Exception as e:
            logger.error(f"loadvm Error: {e}")
        finally:
            await self.disconnect_qmp()
            return ret
        
    async def delvm(self) -> bool:
        logger.info("Deleting snapshot...")
        ret = False
        try:
            await self.connect_qmp()
            if self.node_name is None:
                self.node_name = await self.find_block_device()
            
            args = {
                "job-id": self.generate_snapshot_job_id("delete"), 
                "tag": "mtcfuzz-snapshot", 
                "devices": [f"{self.node_name}"],
            }

            res = await self.qmp.execute("snapshot-delete", args)
            ret = True
        except Exception as e:
            logger.error(f"delvm Error: {e}")
        finally:
            await self.disconnect_qmp()
            if os.path.exists(self.snapshot_created_file):
                os.unlink(self.snapshot_created_file)
            return ret

    def snapshot_created(self) -> bool:
        return os.path.exists(self.snapshot_created_file)
    
    def remove_snapshot_created_file(self) -> None:
        if os.path.exists(self.snapshot_created_file):
            os.remove(self.snapshot_created_file)

    def remove_snapshot(self):
        if os.path.exists(self.qemu_snapshot_storage):
            logger.info(f"Remove old snapshot")
            os.unlink(self.qemu_snapshot_storage)
        
        self.remove_snapshot_created_file()
