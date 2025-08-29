from ..seed_manager import SeedManager
import copy

import pprint
class OPTEEXtest1001SeedManager(SeedManager):
    def __init__(self, seed_dir: str, task_id: int) -> None:
        super().__init__(seed_dir, task_id)

    def create_new_seed(self, seed_id: str, fuzz_params: dict) -> dict:
        data = copy.deepcopy(self.seeds[seed_id])
        seed = data["seed"]

        seed["input_len"]["value"] = hex(fuzz_params["input_len"])
        seed["buffer_len"]["value"] = hex(fuzz_params["buffer_len"])
        return seed