import importlib

def seed_manager_factory(config: dict) -> any:
    try: 
        seed_manager_module = importlib.import_module(config["fuzzing"]["seed_manager"])
        seed_manager_class = config["fuzzing"]["seed_manager_class"]

        return getattr(seed_manager_module, seed_manager_class)
    except ImportError as e:
        print(f"Error importing seed manager module: {e}")
        return None