import subprocess

from core.utils import config
from hitlist.ip_scan import zmap_output_fields, cleanup


def run_zmap_scan(output_file: str, max_ips: int):
    command = [
        "zmap",
        "-o", output_file,
        "-N", str(max_ips),
        "-B", f"{config.send_mbps}M",
        "-M", "icmp_echoscan",
        "--output-fields", zmap_output_fields,
        "--output-filter", "classification=echoreply && repeat=0"
    ]

    subprocess.run(command)


def start(output_file: str, max_ips: int):
    run_zmap_scan(output_file, max_ips)
    cleanup(output_file)
