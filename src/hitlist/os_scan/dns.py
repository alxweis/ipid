import datetime
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import polars as pl

from core.utils import config
from hitlist.os_scan import setup, cleanup, extract_os_name


def process_ip_addr(ip: str, os_scan_file: str):
    try:
        result = subprocess.run(
            ['dig', f'@{ip}', 'version.bind', 'CH', 'TXT', '+short', '+retry=0', '+time=1'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        os_name = extract_os_name(result.stdout)
        timestamp = int(datetime.datetime.now().timestamp())

        if result.returncode == 0 and os_name:
            with open(os_scan_file, 'a') as f:
                f.write(f"{ip},{os_name},{timestamp}\n")
        else:
            print(f"Error: Unable to get OS for IP: {ip}", file=sys.stderr)

    except Exception as e:
        print(f"Exception occurred for IP {ip}: {e}", file=sys.stderr)


def run_dig_dns_scan(ip_addr_file: str, os_scan_file: str):
    print(f"Starting DNS scan of IPs in {ip_addr_file}")
    print(f"Results will be written to {os_scan_file}")

    with open(os_scan_file, 'w') as f:
        f.write(f"{config.ip_col_name},{config.os_col_name},{config.ts_os_col_name}\n")

    ip_lf = pl.scan_csv(ip_addr_file, has_header=False, new_columns=[config.ip_col_name])

    with ThreadPoolExecutor(max_workers=30) as executor:
        for ip_row in ip_lf.rows_streaming():
            ip = ip_row[0]
            executor.submit(process_ip_addr, ip, os_scan_file)


def start(ip_scan_file: str):
    ip_addr_file = setup(ip_scan_file)
    os_scan_file = ip_scan_file + ".os_scan.csv"

    run_dig_dns_scan(ip_addr_file, os_scan_file)
    cleanup(ip_scan_file=ip_scan_file, ip_addr_file=ip_addr_file, os_scan_file=os_scan_file)
