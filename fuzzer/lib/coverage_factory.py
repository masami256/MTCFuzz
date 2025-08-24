import importlib

def coverage_factory(config: dict) -> any:
    try:
        coverage_module = importlib.import_module(config["fuzzing"]["coverage_module"])
        coverage_class = config["fuzzing"]["coverage_class"]

        return getattr(coverage_module, coverage_class)
    except ImportError as e:
        print(f"Error importing fuzzer module: {e}")
        return None