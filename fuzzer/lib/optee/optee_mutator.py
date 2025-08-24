from ..mutator import Mutator

class OPTeeMutator(Mutator):
    def __init__(self) -> None:
        mutations = [
            self.bitflip_i,
            self.byteflip_i,
            self.arith_i,
            self.insert_byte_i,
            self.delete_byte_i,
        ]
                
        super().__init__(mutations)

    def mutate(self, seed: dict) -> dict:
        mutator = self.choose_mutation()
        #print(f"Mutating seed {seed} using {mutator.__name__}")
        return mutator(seed)