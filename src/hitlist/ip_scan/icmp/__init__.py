import os
import subprocess
import time

from core.utils import config, runtime
from hitlist.ip_scan import zmap_output_fields, cleanup


def run_zmap_scan(output_file: str, max_ips: int):
    command = [
        "zmap",
        "-o", output_file,
        "-N", str(max_ips),
        "-B", config.zmap_bandwidth,
        "-M", "icmp_echoscan",
        "--output-fields", zmap_output_fields,
        "--output-filter", "classification=echoreply && repeat=0"
    ]

    subprocess.run(command)


def start(targets_path: str, max_ips: int):
    start_time = time.time()
    targets_file = os.path.join(targets_path, "targets.csv")
    run_zmap_scan(targets_file, max_ips)
    result_file = cleanup(targets_file)
    print(f"ICMP IP-Scan finished: {runtime(start_time)} result=[{result_file}]")
