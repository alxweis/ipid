import os
import subprocess
from datetime import datetime
import re

# sudo python3 create_hitlist.py icmp => targets/icmp/<timestamp>.csv
# sudo python3 create_hitlist.py --protocol tcp --port 80 --os-detection ==> targets/tcp/80/<timestamp>.csv

# --os-detection scans for OS on port 80 on application layer (e.g. http, smtp, ...) and transport layer (tcp, udp)

DIR_PATH = os.path.dirname(os.path.abspath(__file__))


def create_output_dir(protocol: str, port: str, service: str):
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    dir_path = f"targets/{protocol}"
    if protocol in ["tcp", "udp"]:
        dir_path += f"/{port}"
    if protocol == "udp":
        dir_path += f"/{service}"
    dir_path += f"/{timestamp}"
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def convert_metric(value: str) -> str:
    if value.isdigit() and int(value) >= 0:  # Check if the input is a positive integer string, including "0"
        return value

    match = re.fullmatch(r'(\d+)([KkMm]?)', value)
    if not match:
        raise ValueError("Only positive integers (including 0) with an optional K or M suffix are allowed")

    num, suffix = match.groups()
    factor = {'K': 1_000, 'M': 1_000_000}.get(suffix.upper(), 1)
    return str(int(num) * factor)


def create(protocol: str, port: str, service: str, max_ips: str, targets_path: str):
    output_dir = create_output_dir(protocol, port, service)
    if protocol == "icmp":
        subprocess.run(["bash", os.path.join(DIR_PATH, "icmp/scan.sh"), output_dir, convert_metric(max_ips)])
    elif protocol == "tcp":
        subprocess.run(["bash", os.path.join(DIR_PATH, "tcp/scan.sh"), port, output_dir, convert_metric(max_ips)])
    elif protocol == "udp":
        subprocess.run(["bash", os.path.join(DIR_PATH, "udp/scan.sh"), port, service, output_dir, convert_metric(max_ips)])
    elif protocol == "os_detection":
        subprocess.run(["bash", os.path.join(DIR_PATH, "os_detection.sh"), targets_path])
    else:
        print(f"Unknown protocol: {protocol}")
