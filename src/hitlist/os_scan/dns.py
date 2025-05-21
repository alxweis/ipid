import datetime
import json
import os
import subprocess
import sys
import time

from core.utils import config, runtime
from hitlist.os_scan import setup, cleanup, extract_os_name


def run_zdns_scan(ips_tmp_file: str, targets_os_file: str):
    result_count = 0

    print(f"Starting DNS scan for IP addresses in {ips_tmp_file}")
    print(f"Results will be written to {targets_os_file}")

    with open(targets_os_file, 'w') as f:
        f.write(f"{config.ip_col_name},{config.os_col_name},{config.ts_os_col_name},{config.us_os_col_name}\n")

    try:
        with subprocess.Popen(
                [
                    "zdns", "TXT",
                    "--class", "CHAOS",
                    "--name-server-mode",
                    "--override-name", "version.bind",
                    "--input-file", ips_tmp_file,
                    "--retries", "1",
                    "--threads", "200",
                    "--timeout", "5",
                    "--udp-only",
                    "--quiet"
                ],
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1
        ) as zdns_process, open(targets_os_file, 'a') as outfile:

            start_time = time.time()
            processed_count = 0
            last_log_time = start_time

            for line in zdns_process.stdout:
                processed_count += 1

                now = time.time()
                if now - last_log_time >= 1:
                    elapsed = now - start_time
                    processed_rate = processed_count / elapsed if elapsed > 0 else 0
                    result_rate = result_count / elapsed if elapsed > 0 else 0
                    print(
                        f"Processing: processed_ips=[{processed_count}] detected_ips=[{result_count}] processing_rate=[{processed_rate:.0f}] detection_rate=[{result_rate:.0f}]")
                    last_log_time = now

                try:
                    response = json.loads(line.strip())

                    data = response.get('data', {})
                    if not data:
                        print("No Data")
                        continue

                    answers = data.get('answers', [])
                    if answers:
                        ans_datas = []
                        for ans in answers:
                            ans_data = ans.get('data', '')
                            if ans_data:
                                ans_datas.append(ans_data)
                            else:
                                print("Answer Data is empty")
                        server = ",".join(ans_datas)
                    else:
                        print("No Answers")
                        continue

                    if not server:
                        print("No Server Info")
                        continue

                    ip = response.get('name', '')
                    os_name = extract_os_name(server)
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

            return_code = zdns_process.wait()
            if return_code != 0:
                print(f"Warning: zdns exited with code {return_code}", file=sys.stderr)

        print(f"Scan complete. Identified OS for {result_count} out of {processed_count} IPs.")

    except Exception as e:
        print(f"Error running zdns: {str(e)}", file=sys.stderr)


def start(targets_path: str):
    start_time = time.time()
    ips_tmp_file = setup(targets_path)
    targets_os_file = os.path.join(targets_path, "targets_os.csv")
    run_zdns_scan(ips_tmp_file, targets_os_file)
    result_file = cleanup(ips_tmp_file=ips_tmp_file, targets_os_file=targets_os_file)
    print(f"DNS OS-Scan finished: {runtime(start_time)} result=[{result_file}]")
