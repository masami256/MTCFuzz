import asyncio
import json
import os

class CrashedTestcaseManager:
    def __init__(self) -> None:
        self.testcases = []
        self.lock = asyncio.Lock() 

    async def add_crashed_testcase(self, testcase: dict) -> None:
        async with self.lock:
            self.testcases.append(testcase)

    def save_params(self, localdir: str, seed: dict):
        filename = f"{localdir}/saved_seed.json"
        with open(filename, "w") as f:
            json.dump(seed, f, indent=4)

        crash_flag_file = f"{localdir}/crashed.txt"
        testdir = os.path.basename(localdir)
        with open(crash_flag_file, "w") as f:
            f.write(f"{testdir}")
            


