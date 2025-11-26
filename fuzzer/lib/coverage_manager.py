from collections import defaultdict

class CoverageManager:
    def __init__(self) -> None:
        self.cover_a: dict[int, int] = defaultdict(int)
        self.cover_b: dict[int, int] = defaultdict(int)
        self.cover_hashes = {}

    def merge_coverage(self, coverages: tuple[dict, dict]) -> None:
        """
        Merge new coverage dictionaries into global coverage maps.
        """
        new_coverage_a, new_coverage_b = coverages

        for pc, count in new_coverage_a.items():
            self.cover_a[pc] += count

        for pc, count in new_coverage_b.items():
            self.cover_b[pc] += count

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
