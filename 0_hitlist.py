import os
import sys
from hitlist import create


def print_usage(filename):
    print(f"Usage: python {filename} [icmp, tcp, udp] (port)")
    sys.exit(1)


def validate_protocol(filename, protocol):
    if protocol not in ["icmp", "tcp", "udp"]:
        print_usage(filename)


def validate_port(filename, protocol, port):
    if protocol in ["tcp", "udp"] and not port:
        print_usage(filename)


def main():
    filename = os.path.basename(__file__)

    # Check argument count
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print_usage(filename)

    protocol = sys.argv[1]

    # Validate protocol
    validate_protocol(filename, protocol)

    # Determine port
    if protocol in ["tcp", "udp"]:
        port = sys.argv[2] if len(sys.argv) == 3 else ""
        validate_port(filename, protocol, port)
    else:
        port = ""  # For ICMP, port is allowed to be empty

    # Call the create function
    create(protocol, port)


if __name__ == "__main__":
    main()
