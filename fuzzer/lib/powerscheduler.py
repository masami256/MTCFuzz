# AFLFast like power scheduler
import logging
import math

logger = logging.getLogger("mtcfuzz")

class PowerScheduler:
    def __init__(self, assing_energy_function: str, *, beta: float = 1, M: float = 100) -> None:
        self.beta = beta
        self.M = M
        self.MAX_SI = 256 # Maximum value for s(i)

        if assing_energy_function == "aflfast":
            self.assing_enrgy_function = self.assign_energy_aflfast
        elif assing_energy_function == "simple":
            self.assing_enrgy_function = self.assign_energy_simple
        else:
            raise ValueError(f"Unknown energy assignment function: {assing_energy_function}")

    def calculate_alpha(self, seed: dict, total_tested_count: int, total_elapsed_us: int) -> float:
        used_count = seed["total_tested_count"]

        # prevent division by zero
        avg_exec_us = total_elapsed_us / total_tested_count if total_tested_count > 0 else 1
        exec_us = total_elapsed_us / used_count if used_count > 0 else avg_exec_us

        perf_score = 100

        # Performance score calculation based on execution time
        if exec_us * 0.1 > avg_exec_us:
            perf_score = 10
        elif exec_us * 0.2 > avg_exec_us:
            perf_score = 25
        elif exec_us * 0.5 > avg_exec_us:
            perf_score = 50
        elif exec_us * 0.75 > avg_exec_us:
            perf_score = 75
        elif exec_us * 4 < avg_exec_us:
            perf_score = 300
        elif exec_us * 3 < avg_exec_us:
            perf_score = 200
        elif exec_us * 2 < avg_exec_us:
            perf_score = 150

        # Ensure performance score is at least 1
        perf_score = max(perf_score, 1)
        return perf_score

    def assign_energy_aflfast(self, seed: dict, total_tested_count: int, total_elapsed_us: int) -> float:
        # s(i)
        si_raw = max(seed.get("total_tested_count", 0), 1)
        si = min(si_raw, self.MAX_SI)
        # f(i)
        fi = max(seed.get("total_same_coverage_count", 0), 1)

        logger.info(f"Assigning energy for seed {seed['id']} with s(i): {si}, f(i): {fi}")

        # α(i)
        alpha = self.calculate_alpha(seed, total_tested_count, total_elapsed_us)

        log_e = (
            math.log(alpha)
            - math.log(self.beta)
            + si * math.log(2.0)
            - math.log(fi)
        )
        log_M = math.log(self.M)

        if log_e >= log_M:
            e = self.M
        else:
            e = math.exp(log_e)

        logger.info(
            f"Calculated energy for seed {seed['id']}: {e} (α: {alpha}, β: {self.beta}, "
            f"s(i): {si}, f(i): {fi}, log_e: {log_e:.3f})"
        )
        return e

    def assign_energy_simple(self, seed: dict, total_tested_count: int, total_elapsed_us: int) -> float:
        return self.M

    def assign_energy(self, seed: dict, total_tested_count: int, total_elapsed_us: int) -> float:
        return self.assing_enrgy_function(seed, total_tested_count, total_elapsed_us)