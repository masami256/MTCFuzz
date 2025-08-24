class CoverageManager:
    def __init__(self) -> None:
        self.cover_a = {} 
        self.cover_b = {}
        self.cover_hashes = {}

    def merge_coverage(self, coverages: tuple[dict, dict]) -> None:
        """
        Merge new coverage dictionaries into global coverage maps.
        """
        new_coverage_a = coverages[0]
        new_coverage_b = coverages[1]

        def merge(target, new_data):
            for pc, count in new_data.items():
                if pc not in target:
                    target[pc] = count
                else:
                    target[pc] += count

        merge(self.cover_a, new_coverage_a)
        merge(self.cover_b, new_coverage_b)

    def update_coverage_hash(self, seed_id: str, coverage_hash: str) -> None:
        """
        Register a seed_id as having the given coverage hash.
        Uses a set to prevent duplicates and allow fast lookup.
        """
        if coverage_hash not in self.cover_hashes:
            self.cover_hashes[coverage_hash] = set()
        self.cover_hashes[coverage_hash].add(seed_id)

    def count_other_seeds_with_same_coverage(self, coverage_hash: str, seed_id: str) -> int:
        if coverage_hash is None:
            return 0
        
        """
        Count how many other seeds share the same coverage hash.
        """
        if coverage_hash in self.cover_hashes:
            seed_ids = self.cover_hashes[coverage_hash]
            return len(seed_ids) - 1 if seed_id in seed_ids else len(seed_ids)
        return 0
