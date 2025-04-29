import datetime
import json
import subprocess
import sys
import time

from core.utils import config
from hitlist.os_scan import setup, cleanup, extract_os_name


def run_zgrab2_http_scan(ip_addr_file: str, os_scan_file: str):
    result_count = 0

    print(f"Starting HTTP scan of IPs in {ip_addr_file}")
    print(f"Results will be written to {os_scan_file}")

    with open(os_scan_file, 'w') as f:
        f.write(f"{config.ip_col_name},{config.os_col_name},{config.ts_os_col_name}\n")

    try:
        with subprocess.Popen(
                ["zgrab2", "http", "--port", "80", "--input-file", ip_addr_file, "--timeout", "5"],
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1
        ) as zgrab_process, open(os_scan_file, 'a') as outfile:

            start_time = time.time()
            processed_count = 0
            last_log_time = start_time

            for line in zgrab_process.stdout:
                processed_count += 1

                now = time.time()
                if now - last_log_time >= 1:
                    elapsed = now - start_time
                    rate = processed_count / elapsed if elapsed > 0 else 0
                    print(f"Processed {processed_count} IPs, {result_count} with OS detected ({rate:.1f} IPs/sec)")
                    last_log_time = now

                try:
                    data = json.loads(line.strip())

                    server = (
                        data.get('data', {})
                        .get('http', {})
                        .get('result', {})
                        .get('response', {})
                        .get('headers', {})
                        .get('server')
                    )
                    if not server:
                        continue

                    ip = data.get('ip', '')
                    server_str = ",".join(server) if isinstance(server, list) else str(server)
                    os_name = extract_os_name(server_str)
                    timestamp = int(datetime.datetime.now().timestamp())

                    if os_name:
                        outfile.write(f"{ip},{os_name},{timestamp}\n")
                        result_count += 1

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error processing line: {str(e)}", file=sys.stderr)

            return_code = zgrab_process.wait()
            if return_code != 0:
                print(f"Warning: zgrab2 exited with code {return_code}", file=sys.stderr)

        print(f"Scan complete. Identified OS for {result_count} out of {processed_count} IPs.")

    except Exception as e:
        print(f"Error running zgrab2: {str(e)}", file=sys.stderr)


def start(ip_scan_file: str):
    ip_addr_file = setup(ip_scan_file)
    os_scan_file = ip_scan_file + ".os_scan.csv"

    run_zgrab2_http_scan(ip_addr_file, os_scan_file)
    cleanup(ip_scan_file=ip_scan_file, ip_addr_file=ip_addr_file, os_scan_file=os_scan_file)
