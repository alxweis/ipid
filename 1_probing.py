import os
import subprocess
import sys

from probing import PROBING_FILE, MODES

filename = os.path.basename(__file__)


def print_usage():
    print("Usage:")
    print("\n".join([f"python {filename} {mode} <ip|os>" for mode in MODES]))
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print_usage()

    mode = sys.argv[1]
    targets_type = sys.argv[2]
    if mode in MODES:
        process = subprocess.Popen(["go", "run", PROBING_FILE, mode, targets_type])
        try:
            process.wait()
        except KeyboardInterrupt:
            print("Stopping gracefully...")
            process.wait()  # Process should clean up itself
    else:
        print_usage()


if __name__ == "__main__":
    main()
