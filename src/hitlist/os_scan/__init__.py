import os
import re
import subprocess
import sys

import polars as pl

from analysis.main import analyze_response_rate
from core.utils import config

os_regex = "ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos|openembedded|yocto|utm|gaia|router"
os_pattern = re.compile(os_regex, re.IGNORECASE)


def setup(ip_scan_file: str) -> str:
    try:
        # Check if the file exists
        if not os.path.exists(ip_scan_file):
            raise FileNotFoundError(f"Error: File {ip_scan_file} does not exist")

        print("Checking if OS scan was already made...")
        lf = pl.scan_csv(ip_scan_file)
        columns = lf.collect_schema().names()
        if config.os_col_name in columns:
            print(f"Column '{config.os_col_name}' already exists in the CSV file.")
            print("OS fingerprinting will be skipped.")
            raise ValueError("OS column already exists")

        print("Creating file with IP addresses for OS scanning...")
        ip_addr_file = f"{ip_scan_file}.ip_addr.csv"
        unique_ips = lf.select(config.ip_col_name).unique().collect()
        with open(ip_addr_file, 'w') as f:
            f.write(f"{config.ip_col_name}\n")
            for ip in unique_ips[config.ip_col_name]:
                f.write(f"{ip}\n")

        print(f"Setup finished: ip_addr_count=[{len(unique_ips)}] ip_addr_file=[{ip_addr_file}]")

        return ip_addr_file

    except Exception as e:
        print(f"Unexpected error during setup: {str(e)}")
        raise ValueError(f"Failed to prepare IP addresses: {str(e)}")


def merge_ip_os_scan_data(ip_scan_file: str, os_scan_file: str) -> bool:
    try:
        print(f"Merging: {os_scan_file} => {ip_scan_file}")

        print("Reading files...")
        ip_scan_lf = pl.scan_csv(ip_scan_file)
        os_scan_lf = pl.scan_csv(os_scan_file)

        print("Joining files...")
        merged_lf = ip_scan_lf.join(
            os_scan_lf,
            on=config.ip_col_name,
            how="left"
        )

        print("Decompressing target file to temporary file...")
        decompressed_ip_scan_file = ip_scan_file + "_decompressed.csv"
        subprocess.run(["zstd", "-d", ip_scan_file, "-o", decompressed_ip_scan_file], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        print("Writing the merged results back to the temporary file...")
        merged_lf.write_csv(decompressed_ip_scan_file)

        print("Compressing the temporary file to target file...")
        subprocess.run(["zstd", decompressed_ip_scan_file, "-o", ip_scan_file], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

        print("Removing temporary file...")
        os.remove(decompressed_ip_scan_file)

        print("Merge finished")
        return True

    except Exception as e:
        print(f"Error merging scan results: {str(e)}", file=sys.stderr)
        return False


def cleanup(ip_scan_file: str, ip_addr_file: str, os_scan_file: str):
    success = merge_ip_os_scan_data(ip_scan_file=ip_scan_file, os_scan_file=os_scan_file)

    if success:
        try:
            os.remove(ip_addr_file)
            os.remove(os_scan_file)
            print("Temporary files removed.")
        except:
            print("Warning: Could not remove temporary files.")

        analyze_response_rate(targets_file=ip_scan_file, ts_name=config.ts_os_col_name)
        print(f"Results saved in {ip_scan_file}")


def extract_os_name(expression: str) -> str | None:
    match = os_pattern.search(expression.strip().lower())
    if match:
        return match.group(0)  # Return the actual matched OS string
    return None
