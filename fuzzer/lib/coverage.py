import hashlib
from collections import defaultdict

class Coverage:
    def __init__(self, kernel_filter: list, firmware_filter: list, 
                 ignore_kernel_cov: bool, ignore_firmware_cov: bool = False) -> None:
        self.kernel_filter = kernel_filter
        self.firmware_filter = firmware_filter

        self.ignore_kernel_cov = ignore_kernel_cov
        self.ignore_firmware_cov = ignore_firmware_cov

        # Use defaultdict for automatic zero initialization
        self.kernel_cov = defaultdict(int)
        self.firmware_cov = defaultdict(int)
        self.other = defaultdict(int)

    def add_firmware_filter(self, additional_filter: list) -> None:
        self.firmware_filter += additional_filter

    def read_coverage(self, trace_log_file: str) -> list[str]:
        with open(trace_log_file, "r") as f:
            return f.readlines()

    def analyze_coverage(self, cover_pcs: list[str]) -> tuple[bool, bool, str]:
        kernel_cov_found = False
        firmware_cov_found = False

        all_hex = []

        for pc_str in cover_pcs:
            # Convert hex string to integer (e.g., '0x1234abcd' -> int)
            pc = int(pc_str, 16)
            pc_found = False

            for kernel_range in self.kernel_filter:
                lower = int(kernel_range["lower"], 16)
                upper = int(kernel_range["upper"], 16)

                if lower <= pc <= upper:
                    self.kernel_cov[pc] += 1
                    if self.kernel_cov[pc] == 1:
                        kernel_cov_found = True
                    all_hex.append(pc)
                    pc_found = True
                    break


            if not pc_found:
                for firmware_range in self.firmware_filter:
                    lower = int(firmware_range["lower"], 16)
                    upper = int(firmware_range["upper"], 16)

                    if lower <= pc <= upper:
                        self.firmware_cov[pc] += 1
                        if self.firmware_cov[pc] == 1:
                            firmware_cov_found = True
                        all_hex.append(pc)
                        pc_found = True
                        break

            if not pc_found:
                self.other[pc] += 1

        # Generate SHA-256 hash from the list of covered PCs (in hex format)
        h = hashlib.sha256(" ".join(f"{x:#x}" for x in all_hex).encode('utf-8')).hexdigest()

        # Apply ignore flags if set
        if self.ignore_kernel_cov:
            kernel_cov_found = False
        if self.ignore_firmware_cov:
            firmware_cov_found = False

        return kernel_cov_found, firmware_cov_found, h

    def get_coverages(self) -> tuple[dict, dict]:
        return (self.kernel_cov, self.firmware_cov)
