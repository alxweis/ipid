import os
import subprocess
import time

from core.utils import config, runtime
from hitlist.ip_scan import zmap_output_fields, cleanup


def run_zmap_scan(output_file: str, port: str, max_ips: int):
    command = [
        "zmap",
        "-p", port,
        "-o", output_file,
        "-N", str(max_ips),
        "-B", config.zmap_bandwidth,
        "-M", "tcp_synscan",
        "--output-fields", zmap_output_fields,
        "--output-filter", "classification!=icmp && repeat=0"
    ]

    subprocess.run(command)


def start(targets_path: str, port: str, max_ips: int, enable_os_scan: bool):
    start_time = time.time()
    targets_file = os.path.join(targets_path, "targets.csv")
    run_zmap_scan(targets_file, port, max_ips)
    result_file = cleanup(targets_file)
    print(f"TCP({port}) IP-Scan finished: {runtime(start_time)} result=[{result_file}]")

    if enable_os_scan:
        subprocess.run(["python3", "0_hitlist.py", "os_scan", result_file])
