# C005: os.system with user input (command injection)
import os
def run_command(cmd: str) -> str:
    return os.popen(f"echo {cmd}").read()
