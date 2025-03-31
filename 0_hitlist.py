import os
import sys
from hitlist import create


def print_usage(filename):
    print(f"Usage:\npython {filename} icmp (max_count)\npython {filename} tcp [port] (max_count)\npython {filename} udp [port] (max_count)")
    sys.exit(1)


def parse_args():
    if len(sys.argv) < 2:
        print_usage(os.path.basename(__file__))

    protocol = sys.argv[1]
    port = ""
    max_count = 0

    if protocol == "icmp":
        if len(sys.argv) == 3:
            max_count = parse_max_count(sys.argv[2])
    elif protocol in ["tcp", "udp"]:
        if len(sys.argv) < 3:
            print_usage(os.path.basename(__file__))
        port = sys.argv[2]
        if len(sys.argv) == 4:
            max_count = parse_max_count(sys.argv[3])
    else:
        print_usage(os.path.basename(__file__))

    return protocol, port, max_count


def parse_max_count(arg):
    try:
        return int(arg)
    except ValueError:
        print_usage(os.path.basename(__file__))


def main():
    protocol, port, max_count = parse_args()
    create(protocol, port, max_count)


if __name__ == "__main__":
    main()
