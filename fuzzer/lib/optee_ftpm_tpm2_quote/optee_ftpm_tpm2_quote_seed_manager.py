from ..seed_manager import SeedManager
import copy

class OPTEEFtpmTpm2QuoteSeedManager(SeedManager):
    def __init__(self, seed_dir: str, task_id: int) -> None:
        super().__init__(seed_dir, task_id)

    def create_new_seed(self, seed_id: str, fuzz_params: dict) -> dict:
        data = copy.deepcopy(self.seeds[seed_id])
        seed = data["seed"]

        for key in fuzz_params:
            param = fuzz_params[key]
            if seed[key]["type"] == "hex":
                if type(param) == int:
                    param = hex(param)
            
            seed[key]["value"] = param

        return seed