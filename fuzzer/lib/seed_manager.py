import logging
logger = logging.getLogger("mtcfuzz")

import os
import random
import glob
import hashlib
from .fuzzer_lib import *
import pprint

class SeedManager:
    def __init__(self, seed_dir: str, task_id: str) -> None:
        self.seeds = {}
        self.task_id = task_id
        self.read_seed_files(seed_dir)

    def create_seed_id(self, seed: dict) -> str:
        json_str = json.dumps(seed, sort_keys=True)
        return self.task_id + "-" + hashlib.sha256(json_str.encode('utf-8')).hexdigest()

    def find_seed_files(self, seed_dir: str) -> list[str]:
        glob_pattern = os.path.join(seed_dir, "**", "*.json")
        seed_files = glob.glob(glob_pattern, recursive=True)

        return seed_files

    def read_seed_files(self, seed_dir: str) -> None:
        for seed_file in self.find_seed_files(seed_dir):
            json_data = read_json(seed_file)
            sorted_data = {
                k: v for k, v in sorted(json_data.items(), key=lambda item: item[1]["order"])
            }

            seed_id = self.create_seed_id(sorted_data)

            data = {
                "id": seed_id,
                "seed": sorted_data,
                "elapsed_us": 0,
                "traced_pcs_a": {},
                "traced_pcs_b": {},
                "total_trace_length": 0,
                "total_tested_count": 0,
                "total_same_coverage_seed_count": 0,
                "coverage_hash": None,
            }

            self.seeds[seed_id] = data

    def create_new_seed(self, seed_id: str, fuzz_params: dict) -> dict:
        # Create a new seed based on the original seed and fuzz parameters
        pass

    def add_seed(self, seed_id: str, fuzz_params: dict, elapsed_us: int, coverages: tuple) -> None:
        orig_seed = self.seeds[seed_id]
        new_seed = self.create_new_seed(seed_id, fuzz_params)

        if orig_seed["seed"] == new_seed and coverages == (orig_seed["traced_pcs_a"], orig_seed["traced_pcs_b"]):
            self.update_seed(orig_seed, elapsed_us)
            return
        
        new_seed_id = self.create_seed_id(new_seed)

        data = {
            "id": new_seed_id,
            "seed": new_seed,
            "elapsed_us": 1,
            "traced_pcs_a": coverages[0],
            "traced_pcs_b": coverages[1],
            "total_trace_length": len(coverages[0]) + len(coverages[1]),
            "total_tested_count": 1,
            "total_same_coverage_seed_count": 0,
            "coverage_hash": None,
        }
        self.seeds[new_seed_id] = data

        logger.info(f"Added new seed: {new_seed_id}")
        pprint.pprint(new_seed)

    def update_seed(self, seed: dict, elapsed_us: int) -> None:
        if seed["elapsed_us"] == 0:
            seed["elapsed_us"] = elapsed_us

        seed["total_tested_count"] += 1

    def update_coverage_hash(self, seed_id: str, coverage_hash: str, total_same_coverage_seed_count: int) -> None:
        if seed_id in self.seeds:
            self.seeds[seed_id]["coverage_hash"] = coverage_hash
            self.seeds[seed_id]["total_same_coverage_seed_count"] = total_same_coverage_seed_count

    def get_random_seed(self) -> dict | None:
        if not self.seeds:
            return None
        seed = random.choice(list(self.seeds.values()))
        seed["total_tested_count"] += 1
        return seed