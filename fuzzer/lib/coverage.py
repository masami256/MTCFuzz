import hashlib
from collections import defaultdict
from bisect import bisect_right

class Coverage:
    def __init__(self, kernel_filter: list, firmware_filter: list, 
                 ignore_kernel_cov: bool, ignore_firmware_cov: bool = False) -> None:
        self.kernel_filter = self._create_filter(kernel_filter)
        self.kernel_starts = [pair[0] for pair in self.kernel_filter]


        self.firmware_filter = self._create_filter(firmware_filter)
        self.firmware_starts = [pair[0] for pair in self.firmware_filter]

        self.ignore_kernel_cov = ignore_kernel_cov
        self.ignore_firmware_cov = ignore_firmware_cov

        # Use defaultdict for automatic zero initialization
        self.kernel_cov = defaultdict(int)
        self.firmware_cov = defaultdict(int)
        self.other = defaultdict(int)

    def _create_filter(self, filter_list):
        result = []
        for data in filter_list:
            lower = int(data["lower"], 16)
            upper = int(data["upper"], 16)
            result.append([lower, upper])
        result.sort(key=lambda x: x[0])
        return result

    def read_coverage(self, trace_log_file: str) -> list[str]:
        with open(trace_log_file, "r") as f:
            return f.readlines()

    def analyze_coverage(self, cover_pcs: list[str]) -> tuple[bool, bool, str]:
        kernel_cov_found = False
        firmware_cov_found = False

        all_hex = []

        def addr_in_filters(addr, filters, starts):
            idx = bisect_right(starts, addr) - 1
            if idx < 0:
                return False
            lower, upper = filters[idx]
            return lower <= addr <= upper

        for pc_str in cover_pcs:
            # Convert hex string to integer (e.g., '0x1234abcd' -> int)
            pc = int(pc_str, 16)

            # check pc in kernel range
            if pc in self.kernel_cov:
                self.kernel_cov[pc] += 1
                all_hex.append(pc)
                continue
            elif pc in self.firmware_cov:
                self.firmware_cov[pc] += 1
                all_hex.append(pc)
                continue

            if addr_in_filters(pc, self.kernel_filter, self.kernel_starts):
                self.kernel_cov[pc] = 1
                kernel_cov_found = True
                all_hex.append(pc)
                continue
            
            if addr_in_filters(pc, self.firmware_filter, self.firmware_starts):
                self.firmware_cov[pc] = 1
                firmware_cov_found = True
                all_hex.append(pc)
                continue

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
