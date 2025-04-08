import os
import sys
from hitlist import create


def print_usage(filename):
    print("Usage:")
    print(f"python {filename} icmp (max_ips)")
    print(f"python {filename} tcp [port] (max_ips)")
    print(f"python {filename} udp [port] [service] (max_ips)")
    sys.exit(1)


def parse_args():
    filename = os.path.basename(__file__)

    if len(sys.argv) < 2:
        print_usage(filename)

    protocol = sys.argv[1]
    port = ""
    service = ""
    max_ips = "0"

    if protocol == "icmp":
        if len(sys.argv) == 3:
            max_ips = sys.argv[2]
    elif protocol == "tcp":
        if len(sys.argv) < 3:
            print_usage(filename)
        port = sys.argv[2]
        if len(sys.argv) == 4:
            max_ips = sys.argv[3]
    elif protocol == "udp":
        if len(sys.argv) < 4:
            print_usage(filename)
        port = sys.argv[2]
        service = sys.argv[3]
        if len(sys.argv) == 5:
            max_ips = sys.argv[4]
    else:
        print_usage(filename)

    return protocol, port, service, max_ips


def main():
    protocol, port, service, max_ips = parse_args()
    create(protocol, port, service, max_ips)


if __name__ == "__main__":
    main()
