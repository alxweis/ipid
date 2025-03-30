import os
import sys
from hitlist import create

if __name__ == "__main__":
    filename = os.path.basename(__file__)

    if len(sys.argv) != 3:
        print(f"Usage: python {filename} [icmp, tcp, udp] <port>")
        sys.exit(1)

    protocol = sys.argv[1]
    if protocol not in ["icmp", "tcp", "udp"]:
        print(f"Usage: python {filename} [icmp, tcp, udp] <port>")
    port = sys.argv[2]

    create(protocol, port)
