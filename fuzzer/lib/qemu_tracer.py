import logging
logger = logging.getLogger("mtcfuzz")

from qemu.qmp import QMPClient

class QemuTracer:
    def __init__(self, task_id: str, qmp_socket_path: str) -> None:
        super().__init__()
        self.qmp_socket_path = qmp_socket_path
        self.running = True
        self.conn = None
        self.qmp_client_name = f"fuzz-qmp-tracer-{task_id}"
        self.qmp = None

    async def connect_qmp(self) -> bool:
        if self.qmp is None:
            self.qmp = QMPClient(self.qmp_client_name)
            ret = await self.qmp.connect(self.qmp_socket_path)
            return ret
        
    async def disconnect_qmp(self) -> None:
        if self.qmp is not None:
            ret = await self.qmp.disconnect()
            self.qmp = None

    async def tracer_on(self, trace_log: str) -> bool:
        ret = False
        try:
            await self.connect_qmp()

            args = {
                "filename": trace_log, 
            }

            res = await self.qmp.execute("mtcfuzz-trace-start", args)
            ret = True
        except Exception as e:
            logger.error(f"tracer_on Error: {e}")
        finally:
            await self.disconnect_qmp()
            return ret
        
    async def tracer_off(self) -> bool:
        ret = False
        try:
            await self.connect_qmp()

            res = await self.qmp.execute("mtcfuzz-trace-stop", {})
            ret = True
        except Exception as e:
            logger.error(f"tracer_off Error: {e}")
        finally:
            await self.disconnect_qmp()
            return ret
