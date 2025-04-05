import os
import sys
import subprocess
from probing import PROBING_FILE, MODES


if __name__ == "__main__":
    filename = os.path.basename(__file__)

    if len(sys.argv) != 2:
        print("Usage:")
        print("\n".join([f"python {filename} {mode}" for mode in MODES]))
        sys.exit(1)

    mode = sys.argv[1]
    if mode in MODES:
        subprocess.run(["go", "run", PROBING_FILE, mode], check=True)
    else:
        print("Usage:")
        print("\n".join([f"python {filename} {mode}" for mode in MODES]))
        sys.exit(1)
