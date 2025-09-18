import os
import re
import sys
from datetime import datetime

import hitlist
from hitlist.ip_scan import icmp, tcp, udp
from hitlist.os_scan import http, dns

filename = os.path.basename(__file__)


def print_usage():
    print("Usage:")
    print(f"python {filename} ip_scan icmp [max_ips]")
    print(f"python {filename} ip_scan tcp <port> [max_ips] [enable_os_scan]")
    print(f"python {filename} ip_scan udp <port> [max_ips] [enable_os_scan]")
    print(f"python {filename} os_scan <targets_path>")
    sys.exit(1)


def get_command(index: int) -> str | None:
    if len(sys.argv) > index:
        value = sys.argv[index]
        if value in ["ip_scan", "os_scan"]:
            return value
    print_usage()


def get_protocol(index: int) -> str | None:
    if len(sys.argv) > index:
        value = sys.argv[index]
        if value in ["icmp", "tcp", "udp"]:
            return value
    print_usage()


def get_max_ips(index: int) -> int:
    if len(sys.argv) > index:
        value = sys.argv[index]

        if value.isdigit() and int(value) >= 0:
            return int(value)

        match = re.fullmatch(r'(\d+)([KkMm]?)', value)
        if not match:
            raise ValueError("Only positive integers (including 0) with an optional K or M suffix are allowed")

        num, suffix = match.groups()
        factor = {'K': 1_000, 'M': 1_000_000}.get(suffix.upper(), 1)
        return int(num) * factor
    else:
        return 0


def get_port(index: int):
    if len(sys.argv) > index:
        value = sys.argv[index]
        if value.isdigit() and 0 <= int(value) <= 65535:
            return value
    print_usage()


def get_enable_os_scan(index: int) -> bool:
    if len(sys.argv) > index:
        value = sys.argv[index]
        return value.lower() in ["1", "t", "true"]
    else:
        return False


def get_targets_path(index: int) -> (str, str, str | None):
    if len(sys.argv) > index:
        targets_path = sys.argv[index]
        # value has format: targets/<protocol>/<port>/<YYYY-MM-DD_HH-MM-SS>
        pattern = r"^targets/(icmp|tcp|udp)(?:/(\d{1,5}))?/\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$"
        match = re.match(pattern, targets_path)
        if match:
            protocol = match.group(1)
            if protocol == "icmp":
                port = None
            else:
                port = match.group(2)
            return targets_path, protocol, port
    print_usage()


def create_output_dir(protocol: str, port: None | str) -> str:
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    dir_path = f"targets/{protocol}"
    if protocol in ["tcp", "udp"]:
        dir_path += f"/{port}"
    dir_path += f"/{timestamp}"
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def ip_scan(protocol: str, port: None | str, max_ips: int, enable_os_scan: bool):
    print("Starting IP Scan...")
    print(f"Protocol: {protocol.upper()}")
    print(f"Port: {port}")
    print(f"Max IPs: {'No Limit' if max_ips == 0 else max_ips}")
    print(f"Enable OS Scan: {enable_os_scan}")

    targets_path = create_output_dir(protocol, port)
    if protocol == "icmp":
        icmp.start(targets_path=targets_path, max_ips=max_ips, enable_os_scan=enable_os_scan)
    elif protocol == "tcp":
        tcp.start(targets_path=targets_path, port=port, max_ips=max_ips, enable_os_scan=enable_os_scan)
    elif protocol == "udp":
        udp.start(targets_path=targets_path, port=port, max_ips=max_ips, enable_os_scan=enable_os_scan)
    else:
        print_usage()


def os_scan(targets_path: str, protocol: str, port: str | None):
    print("Starting OS Scan...")
    print(f"Targets Directory: {targets_path}")
    print(f"Protocol: {protocol.upper()}")
    print(f"Port: {port}")

    hitlist.os_scan.start(targets_path)


def main():
    command = get_command(1)

    if command == "ip_scan":
        protocol = get_protocol(2)
        if protocol == "icmp":
            ip_scan(protocol, None, get_max_ips(3), False)
        elif protocol in ["tcp", "udp"]:
            ip_scan(protocol, get_port(3), get_max_ips(4), get_enable_os_scan(5))
        else:
            print_usage()
    elif command == "os_scan":
        targets_path, protocol, port = get_targets_path(2)
        os_scan(targets_path, protocol, port)
    else:
        print_usage()


if __name__ == "__main__":
    main()
