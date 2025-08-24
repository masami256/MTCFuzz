import asyncio

class CrashedTestcaseManager:
    def __init__(self) -> None:
        self.testcases = []
        self.lock = asyncio.Lock() 

    async def add_testcase(self, testcase: dict) -> None:
        async with self.lock:
            self.testcases.append(testcase)
