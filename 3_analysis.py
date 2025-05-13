import os
import sys

from analysis.main import start

filename = os.path.basename(__file__)


def print_usage():
    print("Usage:")
    print(f"python {filename} <result_path>")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print_usage()

    result_path = sys.argv[1]
    start(result_path)


if __name__ == "__main__":
    main()
