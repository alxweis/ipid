import os
import signal
import subprocess
import sys

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
        process = subprocess.Popen(["go", "run", PROBING_FILE, mode])
        try:
            process.wait()
        except KeyboardInterrupt:
            print("Stopping gracefully...")
            process.send_signal(signal.SIGINT)
            try:
                process.wait()  # Process should clean up itself
            except KeyboardInterrupt:
                print("Stopping forcefully...")
                process.terminate()
    else:
        print_usage()


if __name__ == "__main__":
    main()
