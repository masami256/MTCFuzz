from ..seed_manager import SeedManager
import copy

class SBISeedManager(SeedManager):
    def __init__(self, seed_dir: str, task_id: int) -> None:
        super().__init__(seed_dir, task_id)

    def create_new_seed(self, seed_id: str, fuzz_params: dict) -> dict:
        data = copy.deepcopy(self.seeds[seed_id])
        seed = data["seed"]
        for reg in seed:
            if reg in fuzz_params:
                seed[reg]["value"] = hex(fuzz_params[reg])
        return seed