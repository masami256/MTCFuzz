from ..seed_manager import SeedManager
import copy

import pprint
class OPTEESeedManager(SeedManager):
    def __init__(self, seed_dir: str, task_id: int) -> None:
        super().__init__(seed_dir, task_id)

    def create_new_seed(self, seed_id: str, fuzz_params: dict) -> dict:
        data = copy.deepcopy(self.seeds[seed_id])
        seed = data["seed"]

        seed["cmd_id"]["value"] = hex(fuzz_params["cmd_id"])
        return seed