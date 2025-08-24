import json
import pprint

def save_cmd_output(buffer: str, output_file: str) -> None:
    if not buffer:
        return
    
    with open(output_file, 'w') as f:
        f.write(buffer)

def read_json(file_path: str) -> dict:
    with open(file_path, 'r') as f:
        return json.load(f)
    
def is_crashed(test_result: str) -> bool:
    console_log = None
    with open(test_result) as f:
        console_log = f.read()
    
    # pprint.pprint(console_log)
    if "sbi_trap_error" in console_log:
        return True
    
    if "TA panicked with code" in console_log:
        return True
    
    if "Kernel panic" in console_log:
        return True
    
    return False