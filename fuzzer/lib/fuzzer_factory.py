import logging
logger = logging.getLogger("mtcfuzz")

import importlib

def fuzzer_factory(config: dict) -> any:
    try: 
        fuzzer_module = importlib.import_module(config["fuzzing"]["fuzzer_module"])
        fuzzer_class = config["fuzzing"]["fuzzer_class"]

        return getattr(fuzzer_module, fuzzer_class)
    except ImportError as e:
        logger.error(f"Error importing fuzzer module: {e}")
        return None