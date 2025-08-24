import random

class Mutator:
    def __init__(self, mutations: list) -> None:
        if not mutations:
            raise ValueError("No mutations available")
            
        self.mutations = mutations

    def choose_mutation(self) -> callable:
        return random.choice(self.mutations)

    def mutate(self, seed: dict) -> dict:
        raise NotImplementedError("Mutate method must be implemented by subclasses")
    
    def hex_to_bytearray(self, seed_str: str, min_bytes: int = 1) -> bytearray:
        seed_int = int(seed_str, 16)
        length = max((seed_int.bit_length() + 7) // 8, min_bytes)
        return bytearray(seed_int.to_bytes(length, byteorder='big'))

    def bitflip_i(self, seed_str: str) -> str:
        # Convert hex string to int
        seed_int = int(seed_str, 16)
        bitlen = seed_int.bit_length() or 1
        # Choose a random bit to flip
        bit_to_flip = 1 << random.randint(0, bitlen - 1)
        # Flip the bit
        mutated_int = seed_int ^ bit_to_flip
        return mutated_int

    def byteflip_i(self, seed_str: str) -> str:
        # Convert hex string to bytearray
        seed_bytes = self.hex_to_bytearray(seed_str)
        if not seed_bytes:
            return seed_str  # No mutation if input is empty
        # Choose a random byte and flip it
        idx = random.randrange(len(seed_bytes))
        seed_bytes[idx] ^= 0xFF
        # Convert back to int and then to hex
        mutated_int = int.from_bytes(seed_bytes, byteorder='big')
        return mutated_int

    def arith_i(self, seed_str: str, delta_range: int = 10) -> str:
        # Convert hex string to bytearray
        seed_bytes = self.hex_to_bytearray(seed_str)
        if not seed_bytes:
            return seed_str
        # Choose a random byte and apply small +/- arithmetic
        idx = random.randrange(len(seed_bytes))
        delta = random.randint(1, delta_range)
        op = random.choice([-1, 1])
        seed_bytes[idx] = (seed_bytes[idx] + op * delta) % 256
        # Convert back to int and then to hex
        mutated_int = int.from_bytes(seed_bytes, byteorder='big')
        return mutated_int

    def insert_byte_i(self, seed_str: str) -> int:
        # Convert hex string to bytearray
        seed_bytes = self.hex_to_bytearray(seed_str)
        # Generate a random byte to insert
        byte_to_insert = random.randint(0, 255)
        # Choose insertion position (0〜len)
        idx = random.randint(0, len(seed_bytes))
        # Insert the byte
        seed_bytes.insert(idx, byte_to_insert)
        # Convert back to int
        mutated_int = int.from_bytes(seed_bytes, byteorder='big')
        return mutated_int
    
    def delete_byte_i(self, seed_str: str) -> int:
        # Convert hex string to bytearray
        seed_bytes = self.hex_to_bytearray(seed_str)
        if len(seed_bytes) <= 1:
            return int(seed_str, 16)  # Do not delete if only 1 byte or less
        # Choose a byte index to delete
        idx = random.randrange(len(seed_bytes))
        # Delete the byte
        del seed_bytes[idx]
        # Convert back to int
        mutated_int = int.from_bytes(seed_bytes, byteorder='big')
        return mutated_int