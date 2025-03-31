import os
import subprocess
from datetime import datetime
import re

# sudo python3 create_hitlist.py icmp => targets/icmp/<timestamp>.csv
# sudo python3 create_hitlist.py --protocol tcp --port 80 --os-detection ==> targets/tcp/80/<timestamp>.csv

# --os-detection scans for OS on port 80 on application layer (e.g. http, smtp, ...) and transport layer (tcp, udp)

DIR_PATH = os.path.dirname(os.path.abspath(__file__))


def create_output_dir(protocol: str, port: str):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    dir_path = f"targets/{protocol}"
    if protocol in ["tcp", "udp"]:
        dir_path += f"/{port}"
    dir_path += f"/{timestamp}"
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def convert_metric(value: str):
    if isinstance(value, int) and value >= 0:  # Allow 0 as a valid input
        return value

    match = re.fullmatch(r'(\d+)([KkMm]?)', value)
    if not match:
        raise ValueError("Only positive integers (including 0) with an optional K or M suffix are allowed")

    num, suffix = match.groups()
    factor = {'K': 1_000, 'M': 1_000_000}.get(suffix.upper(), 1)
    return int(num) * factor


def create(protocol: str, port: str, max_count: str):
    output_dir = create_output_dir(protocol, port)
    if protocol == "icmp":
        subprocess.run(["bash", os.path.join(DIR_PATH, "icmp/scan.sh"), output_dir, convert_metric(max_count)])
    elif protocol == "tcp":
        pass
    elif protocol == "udp":
        pass
    else:
        pass
