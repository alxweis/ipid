import datetime
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import config
from hitlist.os_scan import setup, cleanup, extract_os_name

# Lock for synchronizing file writes
write_lock = threading.Lock()

# Initialize counters for logging
processed_count = 0
result_count = 0
start_time = time.time()


def process_ip_addr(ip: str, os_scan_file: str):
    global processed_count, result_count

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
            # Synchronized writing to the file
            with write_lock:
                with open(os_scan_file, 'a') as f:
                    f.write(f"{ip},{os_name},{timestamp}\n")

            # Increment result_count when OS is detected
            with threading.Lock():
                result_count += 1

        # Increment processed_count for each IP processed
        with threading.Lock():
            processed_count += 1

        # Log progress every 1000 processed IPs
        if processed_count % 1000 == 0:
            elapsed_time = time.time() - start_time
            rate = processed_count / elapsed_time
            print(f"Processed {processed_count} IPs, {result_count} with OS detected ({rate:.1f} IPs/sec)")

    except Exception as e:
        print(f"Exception occurred for IP {ip}: {e}", file=sys.stderr)


def run_dig_dns_scan(ip_addr_file: str, os_scan_file: str):
    print(f"Starting DNS scan: input_file=[{ip_addr_file}] output_file=[{os_scan_file}]")

    with open(os_scan_file, 'w') as f:
        f.write(f"{config.ip_col_name},{config.os_col_name},{config.ts_os_col_name}\n")

    futures = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        with open(ip_addr_file, 'r') as f:
            for line in f:
                ip = line.strip()
                future = executor.submit(process_ip_addr, ip, os_scan_file)
                futures.append(future)

        # Wait for all futures to complete and handle any exceptions
        for future in as_completed(futures):
            future.result()  # Optional: can catch errors that occurred in the thread


def start(ip_scan_file: str):
    ip_addr_file = setup(ip_scan_file)
    os_scan_file = ip_scan_file + ".os_scan.csv"

    run_dig_dns_scan(ip_addr_file, os_scan_file)
    cleanup(ip_scan_file=ip_scan_file, ip_addr_file=ip_addr_file, os_scan_file=os_scan_file)
