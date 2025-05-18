import datetime
import json
import os.path
import subprocess
import sys
import time

from core.utils import config, runtime
from hitlist.os_scan import setup, cleanup, extract_os_name


def run_zgrab2_http_scan(ips_tmp_file: str, targets_os_file: str):
    result_count = 0

    print(f"Starting HTTP scan for IP addresses in {ips_tmp_file}")
    print(f"Results will be written to {targets_os_file}")

    with open(targets_os_file, 'w') as f:
        f.write(f"{config.ip_col_name},{config.os_col_name},{config.ts_os_col_name},{config.us_os_col_name}\n")

    try:
        with subprocess.Popen(
                [
                    "zgrab2", "http",
                    "--port", "80",
                    "--input-file", ips_tmp_file,
                    "--senders", "4000",
                    "--timeout", "3s",
                    "--method", "HEAD",
                    "--max-size", "8",
                    "--raw-headers",
                    "--user-agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:114.0) Gecko/20100101 Firefox/114.0",
                    "--flush"
                ],
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1
        ) as zgrab2_process, open(targets_os_file, 'a') as outfile:

            start_time = time.time()
            processed_count = 0
            last_log_time = start_time

            for line in zgrab2_process.stdout:
                processed_count += 1

                now = time.time()
                if now - last_log_time >= 1:
                    elapsed = now - start_time
                    rate = processed_count / elapsed if elapsed > 0 else 0
                    print(
                        f"Processed {processed_count} IPAddresses, {result_count} with OS detected ({rate:.1f} IPAddresses/s)")
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
                    now = datetime.datetime.now()
                    ts_seconds = int(now.timestamp())
                    ts_microseconds = now.microsecond

                    if os_name:
                        outfile.write(f"{ip},{os_name},{ts_seconds},{ts_microseconds}\n")
                        result_count += 1

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error processing line: {str(e)}", file=sys.stderr)

            return_code = zgrab2_process.wait()
            if return_code != 0:
                print(f"Warning: zgrab2 exited with code {return_code}", file=sys.stderr)

        print(f"Scan complete. Identified OS for {result_count} out of {processed_count} IPs.")

    except Exception as e:
        print(f"Error running zgrab2: {str(e)}", file=sys.stderr)


def start(targets_path: str):
    start_time = time.time()
    ips_tmp_file = setup(targets_path)
    targets_os_file = os.path.join(targets_path, "targets_os.csv")
    run_zgrab2_http_scan(ips_tmp_file, targets_os_file)
    result_file = cleanup(ips_tmp_file=ips_tmp_file, targets_os_file=targets_os_file)
    print(f"HTTP OS-Scan finished: {runtime(start_time)} result=[{result_file}]")
