import os
import sys
import subprocess
from probing import PROBING_FILE, MODES

filename = os.path.basename(__file__)


def print_usage():
    print("Usage:")
    print("\n".join([f"python {filename} {mode}" for mode in MODES]))
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print_usage()

    mode = sys.argv[1]
    if mode in MODES:
        try:
            subprocess.run(["go", "run", PROBING_FILE, mode], check=True)
        except subprocess.CalledProcessError as e:
            print("Stopped probing")
    else:
        print_usage()


if __name__ == "__main__":
    main()
