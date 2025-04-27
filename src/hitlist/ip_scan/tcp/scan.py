import subprocess

from core.utils import config
from hitlist.ip_scan import zmap_output_fields, cleanup


def run_zmap_scan(output_file: str, port: str, max_ips: int):
    command = [
        "zmap",
        "-p", port,
        "-o", output_file,
        "-N", str(max_ips),
        "-B", f"{config.send_mbps}M",
        "-M", "tcp_synscan",
        "--output-fields", zmap_output_fields,
        "--output-filter", "classification!=icmp && repeat=0"
    ]

    subprocess.run(command)


def start(output_file: str, port: str, max_ips: int, enable_os_scan: bool):
    run_zmap_scan(output_file, port, max_ips)
    cleanup(output_file)

    if enable_os_scan:
        subprocess.run(["python3", "0_hitlist.py", "os_scan", output_file])
