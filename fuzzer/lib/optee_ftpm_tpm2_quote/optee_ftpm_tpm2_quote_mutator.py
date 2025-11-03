from ..mutator import Mutator
from typing import Any
import random
import string

class OPTeeFtpmTpm2QuoteMutator(Mutator):
    def __init__(self) -> None:
        mutations = [
            self.bitflip_i,
            self.byteflip_i,
            self.arith_i,
            self.insert_byte_i,
            self.delete_byte_i,
        ]
                
        super().__init__(mutations)

    def mutate(self, seed: Any) -> Any:
        mutator = self.choose_mutation()
        #print(f"Mutating seed {seed} using {mutator.__name__}")
        return mutator(seed)
    
    def create_random_charactors(self, size: int) -> str:
        chars = [random.choice(string.printable[:-6]) for _ in range(size)]
        hex_list = [f"0x{ord(c):02x}" for c in chars]
        return " ".join(hex_list)

    def custom_mutater(self, key: str, seed: Any) -> Any:
        if key == "qualifyingData_value":
            size = random.randint(int(seed["min_len"], 16), int(seed["max_len"], 16))
            return self.create_random_charactors(size)
        elif key == "invalid_sessions_tag":
            tags = [0x0, 0x8001, 0x8002, 0x8003, 0x1234, 0xffff, 0x7fff]
            idx = tags[random.randint(0, len(tags) -1)]
            return hex(idx)
        elif key == "invalid_sessions_value":
            size = random.randint(int(seed["min_len"], 16), int(seed["max_len"], 16))
            return self.create_random_charactors(size)

        raise Exception(f"Unknown key {key}")
    
    def mutate_string(self, seed: Any, min_len: str, max_len: str) -> Any:
        min_l= int(min_len, 16)
        max_l = int(max_len, 16)

        tmp = self.create_random_string(min_l, max_l, True).encode("utf-8")
        arr = []
        for c in tmp:
            arr.append(f"{c:02x}")
        return "".join(arr)
