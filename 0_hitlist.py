import os
import sys
from hitlist import create


def print_usage(filename):
    print(f"Usage:\npython {filename} icmp (max_ips)\npython {filename} tcp [port] (max_ips)\npython {filename} udp [port] (max_ips)")
    sys.exit(1)


def parse_args():
    filename = os.path.basename(__file__)

    if len(sys.argv) < 2:
        print_usage(filename)

    protocol = sys.argv[1]
    port = ""
    max_ips = "0"

    if protocol == "icmp":
        if len(sys.argv) == 3:
            max_ips = sys.argv[2]
    elif protocol in ["tcp", "udp"]:
        if len(sys.argv) < 3:
            print_usage(filename)
        port = sys.argv[2]
        if len(sys.argv) == 4:
            max_ips = sys.argv[3]
    else:
        print_usage(filename)

    return protocol, port, max_ips


def main():
    protocol, port, max_ips = parse_args()
    create(protocol, port, max_ips)


if __name__ == "__main__":
    main()
