class SSHError(Exception):
    """
    Custom exception class for SSH errors.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"SSHError: {self.message}"

class SSHTimeoutError(Exception):
    """
    Custom exception class for SSH timeout errors.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self):
        return f"SSHError: {self.message}"