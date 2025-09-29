from ..mutator import Mutator
from typing import Any
import random

class OPTeeFtpmMutator(Mutator):
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
    
    def custom_mutater(self, key: str, seed: Any) -> Any:
        a = [1, 2, 4, 8]
        if key == "flag0":
            return hex(a[random.randint(0, 3)])
    
        raise Exception(f"Unknown key {key}")
    
    def mutate_string(self, seed: Any, min_len: str, max_len: str) -> Any:
        min_l= int(min_len, 16)
        max_l = int(max_len, 16)


        tmp = self.create_random_string(min_l, max_l, True).encode("utf-8")
        arr = []
        for c in tmp:
            arr.append(f"{c:02x}")
        return "".join(arr)
