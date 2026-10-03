import contextlib
from pathlib import Path

SAFE_DIR = "/var/app/uploads"

def read_fixed_file_safe():
    path = Path(SAFE_DIR) / "readme.txt"
    with open(path) as f:
        return f.read()

def resource_managed_safe(path):
    with contextlib.closing(open(path)) as f:
        return f.read()
