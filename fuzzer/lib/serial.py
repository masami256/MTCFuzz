import socket
import select

class Serial:
    def __init__(self, serial_socket_path: str, logfile_path: str, *, debug: bool = False) -> None:
        self.serial_socket_path = serial_socket_path
        self.logfile_path = logfile_path
        self.debug = debug
        self.conn = None
        self.logfile = None

    def open(self) -> None:
        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.conn.connect(self.serial_socket_path)
        self.logfile = open(self.logfile_path, "wb")

    def read(self, *, timeout: float = 0.01, max_loops: int = 50) -> None:
        """
        Read data from serial socket until no new data arrives for `max_loops * timeout` seconds.
        """
        silent_loops = 0
        while silent_loops < max_loops:
            rlist, _, _ = select.select([self.conn], [], [], timeout)
            if rlist:
                data = self.conn.recv(8192)
                if not data:
                    break
                self.logfile.write(data)
                if self.debug:
                    pass
                    # print(f"Received {len(data)} bytes")
                    # print(data.decode(errors="ignore"), end="")
                silent_loops = 0
            else:
                silent_loops += 1
        # self.logfile.flush()

    def close(self) -> None:
        if self.logfile:
            self.logfile.close()
        if self.conn:
            self.conn.close()

    # def __enter__(self):
    #     self.open()
    #     return self

    # def __exit__(self, exc_type, exc_val, exc_tb):
    #     self.close()
