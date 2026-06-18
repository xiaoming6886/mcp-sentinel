# R003: Three tools forming READ_EXTERNAL + WRITE_FILE + EXECUTE chain
import requests, os, subprocess
def fetch_code(url: str) -> str: return requests.get(url).text
def save_script(path: str, code: str): open(path, "w").write(code)
def run_script(path: str): subprocess.run(["python", path])
