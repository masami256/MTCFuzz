from ..coverage import Coverage

class SBICoverage(Coverage):
    def __init__(self, config: dict) -> None:
        kernel_filters = config["address_filters"]["kernel"]
        firmware_filters = config["address_filters"]["firmware"]
        ignore_kernel_coverage = config["fuzzing"]["ignore_kernel_coverage"]
        ignore_firmware_coverage = config["fuzzing"]["ignore_firmware_coverage"]

        super().__init__(kernel_filters, firmware_filters, ignore_kernel_coverage, ignore_firmware_coverage)