import os
import re
import sys

import polars as pl

from core.utils import config
from hitlist import get_csv_header_linux_low_ram, extract_column_no_header, count_rows_linux_low_ram, decompress_csv, \
    compress_csv, join_csv_linux_low_ram

os_regex = "ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos|openembedded|yocto|utm|gaia|router"
os_pattern = re.compile(os_regex, re.IGNORECASE)


def setup(ip_scan_file: str) -> (str, str):
    try:
        # Check if the file exists
        if not os.path.exists(ip_scan_file):
            raise FileNotFoundError(f"Error: File {ip_scan_file} does not exist")

        lf = None
        if config.is_linux_low_ram:
            print("Decompressing file...")
            ip_scan_file = decompress_csv(ip_scan_file)
        else:
            lf = pl.scan_csv(ip_scan_file)

        print("Checking if OS scan was already made...")
        if config.is_linux_low_ram:
            header_line = get_csv_header_linux_low_ram(ip_scan_file)
            columns = header_line.split(',')
        else:
            columns = lf.collect_schema().names()
        if config.os_col_name in columns:
            print(f"Column '{config.os_col_name}' already exists in the CSV file.")
            print("OS fingerprinting will be skipped.")
            raise ValueError("OS column already exists")

        print("Creating file with IP addresses for OS scanning...")
        ip_addr_file = f"{ip_scan_file}.ip_addr.txt"
        if config.is_linux_low_ram:
            extract_column_no_header(input_csv=ip_scan_file, column_name=config.ip_col_name, output_txt=ip_addr_file)
            ip_addr_count = count_rows_linux_low_ram(ip_addr_file)
        else:
            ip_addresses = lf.select(config.ip_col_name).collect()
            ip_addr_count = len(ip_addresses)
            with open(ip_addr_file, 'w') as f:
                for ip in ip_addresses[config.ip_col_name]:
                    f.write(f"{ip}\n")

        print(f"Setup finished: ip_addr_count=[{ip_addr_count}] ip_addr_file=[{ip_addr_file}]")

        return ip_addr_file, ip_scan_file

    except Exception as e:
        print(f"Unexpected error during setup: {str(e)}")
        raise ValueError(f"Failed to prepare IP addresses: {str(e)}")


def merge_ip_os_scan_data(ip_scan_file: str, os_scan_file: str) -> (bool, str):
    try:
        print(f"Merging: {os_scan_file} => {ip_scan_file}")

        if config.is_linux_low_ram:
            merged_scan_file = join_csv_linux_low_ram(original_csv=ip_scan_file, join_csv=os_scan_file,
                                                      join_column_name=config.ip_col_name)
        else:
            print("Reading files...")
            ip_scan_lf = pl.scan_csv(ip_scan_file)
            os_scan_lf = pl.scan_csv(os_scan_file)

            print("Joining files...")
            merged_lf = ip_scan_lf.join(
                os_scan_lf,
                on=config.ip_col_name,
                how="inner"
            )

            print("Decompressing target file...")
            merged_scan_file = decompress_csv(ip_scan_file)

            print("Writing the merged results to the decompressed file...")
            merged_lf.sink_csv(merged_scan_file)

        print("Compressing the merged file...")
        merged_scan_file = compress_csv(merged_scan_file)
        return True, merged_scan_file

    except Exception as e:
        print(f"Error merging scan results: {str(e)}", file=sys.stderr)
        return False, None


def cleanup(ip_scan_file: str, ip_addr_file: str, os_scan_file: str):
    success, ip_scan_file = merge_ip_os_scan_data(ip_scan_file=ip_scan_file, os_scan_file=os_scan_file)

    if success:
        try:
            pass
            # os.remove(ip_addr_file) # TODO Uncomment later
            # os.remove(os_scan_file)
        except:
            print("Warning: Could not remove temporary files.")

        # # Analyze
        # analyze_response_rate(targets_file=ip_scan_file, ts_name=config.ts_os_col_name)
        print(f"Results saved in {ip_scan_file}")


def extract_os_name(expression: str) -> str | None:
    match = os_pattern.search(expression.strip().lower())
    if match:
        return match.group(0)  # Return the actual matched OS string
    return None
