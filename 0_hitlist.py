import os
import re
import subprocess
import sys
from datetime import datetime

from hitlist import ICMP_IP_SCANNER, TCP_IP_SCANNER, UDP_IP_SCANNER, HTTP_OS_SCANNER, DNS_OS_SCANNER

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


def get_targets_path(index: int) -> (str, str, str):
    if len(sys.argv) > index:
        targets_path = sys.argv[index]
        # value has format: targets/<protocol>/<port>/<YYYY-MM-DD_HH-MM-SS>/targets.csv.zst
        pattern = r"^targets/(icmp|tcp|udp)/(\d{1,5})/\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}/targets\.csv\.zst$"
        match = re.match(pattern, targets_path)
        if match:
            protocol = match.group(1)
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
    print(f"Max IPs: {'no limit' if max_ips == 0 else max_ips}")
    print(f"Enable OS Scan: {enable_os_scan}")

    output_dir = create_output_dir(protocol, port)
    if protocol == "icmp":
        subprocess.run(["bash", ICMP_IP_SCANNER, output_dir, str(max_ips)])
    elif protocol == "tcp":
        subprocess.run(["bash", TCP_IP_SCANNER, output_dir, port, str(max_ips), str(enable_os_scan)])
    elif protocol == "udp":
        subprocess.run(["bash", UDP_IP_SCANNER, output_dir, port, str(max_ips), str(enable_os_scan)])
    else:
        print_usage()


def os_scan(targets_path: str, protocol: str, port: str):
    print("Starting OS Scan...")
    print(f"Targets Directory: {targets_path}")
    print(f"Protocol: {protocol.upper()}")
    print(f"Port: {port}")

    if port == "80":
        subprocess.run(["bash", HTTP_OS_SCANNER, targets_path])
    elif port == "53":
        subprocess.run(["bash", DNS_OS_SCANNER, targets_path])
    else:
        print(f"OS scan is not supported for port {port}!")


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
