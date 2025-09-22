import csv
import io
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import duckdb
import zstandard as zstd

from core.utils import config, compress_file, runtime


def setup(targets_path: str) -> str:
    targets_file = os.path.join(targets_path, "targets.csv.zst")
    ips_tmp_file = os.path.join(targets_path, "ips.tmp")

    with open(targets_file, "rb") as f, open(ips_tmp_file, "w") as out:
        dc = zstd.ZstdDecompressor()
        stream = dc.stream_reader(f)
        reader = csv.reader(io.TextIOWrapper(stream))

        header = next(reader)
        ip_index = header.index(config.ip_col_name)

        for row in reader:
            out.write(row[ip_index] + "\n")

    return ips_tmp_file


def cleanup(ips_tmp_file: str, targets_os_file: str) -> str:
    os.remove(ips_tmp_file)
    return compress_file(targets_os_file)


def extract_os_name(expression: str) -> str | None:
    match = os_pattern.search(expression.strip().lower())
    if match:
        return match.group(0)  # Return the actual matched OS string
    return None


def run_port_scan(ips_tmp_file: str) -> (str, str, str):
    base_dir = os.path.dirname(ips_tmp_file)
    output_file = os.path.join(base_dir, "output.xml")

    print(f"Starting Port-Scan for {ips_tmp_file}...")

    process = subprocess.Popen([
        "masscan",
        "-iL", ips_tmp_file,
        "-p22,161,80",
        "--rate", "30000",
        "-oX", output_file
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)

    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            line = output.strip()
            print(line)  # Live output

    print(f"Port-Scan finished: result={output_file}")

    services = {
        "22": "ssh",
        "161": "snmp",
        "80": "http",
    }

    # Initialize IP sets for each service
    service_ips = {service: set() for service in services.values()}

    # Parse XML and categorize IPs by open ports
    for event, elem in ET.iterparse(output_file, events=("end",)):
        if elem.tag == "host":
            ip = elem.find("address").get("addr")
            ports = elem.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_id = port.get("portid")
                    if port_id in services:
                        service_ips[services[port_id]].add(ip)
            elem.clear()

    # Write IP lists and collect file paths
    service_files = {}
    for service, ips in service_ips.items():
        if ips:  # Only create files for services with IPs
            filename = os.path.join(base_dir, f"{service}_ips.txt")
            with open(filename, "w") as f:
                f.writelines(f"{ip}\n" for ip in ips)

            print(f"Saved {len(ips)} IP addresses for {service.upper()} in {filename}")
            service_files[service] = filename
        else:
            service_files[service] = None

    return (
        service_files.get("snmp"),
        service_files.get("ssh"),
        service_files.get("http"),
    )


def run_scanner(executable: str, mode: str, ips_file: str) -> str:
    print(f"Starting {mode.upper()} OS-Scan...")
    process = subprocess.Popen(
        [executable, mode, ips_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )

    output_lines = []
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            line = output.strip()
            print(line)  # Live output
            output_lines.append(line)

    # Parse results
    last_line = output_lines[-1]
    parts = last_line.split()

    output_file = parts[0]
    processed = parts[1]
    success_count = parts[2]
    print(f"{mode.upper()} OS-Scan finished: result={output_file} processed={processed} success={success_count}")
    return output_file


def run_http_scan(ips_tmp_file: str) -> str:
    print(f"Starting HTTP scan for IP addresses in {ips_tmp_file}")
    result_count = 0
    output_file = os.path.join(os.path.dirname(ips_tmp_file), "http_os_info.csv.zst")

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
        ) as zgrab2_process:

            # Zstd Writer setup
            with open(output_file, 'wb') as f:
                compressor = zstd.ZstdCompressor()
                with compressor.stream_writer(f) as writer:
                    text_writer = io.TextIOWrapper(writer, encoding='utf-8', newline='\n')

                    # CSV Header
                    text_writer.write("IP,HTTP_OS_INFO\n")

                    start_time = time.time()
                    processed_count = 0
                    last_log_time = start_time

                    for line in zgrab2_process.stdout:
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

                            if server_str:
                                # Escape quotes for CSV
                                escaped_server = server_str.replace('"', '""')
                                text_writer.write(f'{ip},"{escaped_server}"\n')
                                result_count += 1

                                # Flush periodically
                                if result_count % 1000 == 0:
                                    text_writer.flush()

                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            print(f"Error processing line: {str(e)}", file=sys.stderr)

                    # Final flush
                    text_writer.flush()

            return_code = zgrab2_process.wait()
            if return_code != 0:
                print(f"Warning: zgrab2 exited with code {return_code}", file=sys.stderr)

        print(f"Scan complete. Identified OS for {result_count} out of {processed_count} IPs.")
        return output_file

    except Exception as e:
        print(f"Error running zgrab2: {str(e)}", file=sys.stderr)


def run_dns_scan(ips_tmp_file: str) -> str:
    print(f"Starting DNS scan for IP addresses in {ips_tmp_file}")
    result_count = 0
    output_file = os.path.join(os.path.dirname(ips_tmp_file), "dns_os_info.csv.zst")

    try:
        with subprocess.Popen(
                [
                    "zdns", "TXT",
                    "--class", "CHAOS",
                    "--name-server-mode",
                    "--override-name", "version.bind",
                    "--input-file", ips_tmp_file,
                    "--retries", "1",
                    "--threads", "400",
                    "--timeout", "5",
                    "--udp-only",
                    "--quiet"
                ],
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1
        ) as zdns_process:

            # Zstd Writer setup
            with open(output_file, 'wb') as f:
                compressor = zstd.ZstdCompressor()
                with compressor.stream_writer(f) as writer:
                    text_writer = io.TextIOWrapper(writer, encoding='utf-8', newline='\n')

                    # CSV Header
                    text_writer.write("IP,DNS_OS_INFO\n")

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

                            data = response.get('results', {}).get('TXT', {}).get('data', {})
                            if not data:
                                continue

                            answers = data.get('answers', [])
                            if answers:
                                infos = []
                                for ans in answers:
                                    info = ans.get('answer', '')
                                    if info:
                                        infos.append(info)
                                server_str = ",".join(infos)
                            else:
                                continue

                            if not server_str:
                                continue

                            resolver_info = data.get('resolver', '')
                            if not resolver_info:
                                continue

                            ip = resolver_info.split(':')[0]

                            if server_str:
                                # Escape quotes for CSV
                                escaped_server = server_str.replace('"', '""')
                                text_writer.write(f"{ip},{escaped_server}\n")
                                result_count += 1

                                # Flush periodically
                                if result_count % 1000 == 0:
                                    text_writer.flush()

                        except json.JSONDecodeError:
                            continue
                        except Exception as e:
                            print(f"Error processing line: {str(e)}", file=sys.stderr)

                    # Final flush
                    text_writer.flush()

            return_code = zdns_process.wait()
            if return_code != 0:
                print(f"Warning: zdns exited with code {return_code}", file=sys.stderr)

        print(f"Scan complete. Identified OS for {result_count} out of {processed_count} IPs.")
        return output_file

    except Exception as e:
        print(f"Error running zdns: {str(e)}", file=sys.stderr)


def run_os_scan(ips_tmp_file: str, targets_os_file: str):
    # snmp_ips_file, ssh_ips_file, http_ips_file = run_port_scan(ips_tmp_file)
    #
    # go_file = os.path.join(os.path.dirname(__file__), "main.go")
    # executable = os.path.join(os.path.dirname(__file__), "scanner")
    # subprocess.run(["go", "build", "-o", executable, go_file], check=True, cwd=os.path.dirname(__file__))

    # TODO Revert this later
    snmp_result_file = "targets/udp/53/2025-05-27_11-28-43/snmp_os_info.csv.zst"  # run_scanner(executable, "snmp", snmp_ips_file)
    ssh_result_file = "targets/udp/53/2025-05-27_11-28-43/ssh_os_info.csv.zst"  # un_scanner(executable, "ssh", ssh_ips_file)
    http_result_file = "targets/udp/53/2025-05-27_11-28-43/http_os_info.csv.zst"  # run_http_scan(http_ips_file)

    con = duckdb.connect()
    query = f"""
    COPY (
        SELECT
            COALESCE(snmp.IP, ssh.IP, http.IP) AS IP,
    
            COALESCE(
              REGEXP_EXTRACT(
                COALESCE(
                  NULLIF(snmp.SNMP_OS_INFO,''),
                  NULLIF(ssh.SSH_OS_INFO,''),
                  NULLIF(http.HTTP_OS_INFO,'')
                ),
                '(?i)({os_pattern_str})'
              ),
              ''
            ) AS OS,
    
            COALESCE(snmp.SNMP_OS_INFO, '')   AS SNMP_OS_INFO,
            COALESCE(ssh.SSH_OS_INFO, '')     AS SSH_OS_INFO,
            COALESCE(http.HTTP_OS_INFO, '')   AS HTTP_OS_INFO,
    
        FROM read_csv_auto('{snmp_result_file}') snmp
        FULL OUTER JOIN read_csv_auto('{ssh_result_file}') ssh USING (IP)
        FULL OUTER JOIN read_csv_auto('{http_result_file}') http USING (IP)
    ) TO '{targets_os_file}' (FORMAT CSV, COMPRESSION ZSTD, HEADER);
    """
    con.execute(query)

    # Cleanup # TODO Add back later
    # os.remove(snmp_ips_file)
    # os.remove(ssh_ips_file)
    # os.remove(http_ips_file)
    #
    # os.remove(snmp_result_file)
    # os.remove(ssh_result_file)
    # os.remove(http_result_file)


def start(targets_path: str):
    start_time = time.time()
    ips_tmp_file = setup(targets_path)
    targets_os_file = os.path.join(targets_path, "targets_os.csv.zst")
    run_os_scan(ips_tmp_file, targets_os_file)
    # os.remove(ips_tmp_file) # TODO Revert this later
    print(f"OS-Scan finished: {runtime(start_time)} result=[{targets_os_file}]")


linux_distros = [
    "ubuntu", "centos", "debian", "redhat", "ret hat", "rhel", "fedora", "gentoo", "opensuse", "euleros", "zorin",
    "linux"
]
windows = [
    "windows server", "windows", "win"
]
bsd = [
    "freebsd", "openbsd", "netbsd", "bsd"
]
apple = [
    "macos", "darwin"
]
server = ['server']
router = ['router']

oses = [
    "ubuntu", "centos", "debian", "redhat", "ret hat", "rhel", "fedora", "gentoo", "opensuse", "euleros", "zorin",
    "linux", "windows server", "windows", "win", "freebsd", "openbsd", "netbsd", "bsd", "macos", "darwin", "solaris",
    "fritz", "rasp", "openwrt", "lede", "dd-wrt", "ddwrt", "wrt", "vyos", "vyatta", "pfsense", "routeros", "mikrotik",
    "edgeos", "airos", "unifi", "ubiquiti", "junos", "juniper", "cisco ios", "ios-xe", "nx-os", "ios", "cisco",
    "fortios", "fortinet", "forti", "sonicos", "sonicwall", "sonic", "arubaos", "aruba", "draytek", "drayos", "vigor",
    "dray", "zynos", "zyxel", "aix", "hp-ux", "hpux", "z/os", "zos", "openvms", "vms", "vrp", "busybox", "vxworks",
    "qnx", "freertos", "openembedded", "yocto", "utm", "gaia", "router", "server"
]
os_pattern = re.compile("|".join(oses), re.IGNORECASE)
os_pattern_str = "|".join(re.escape(x) for x in oses)
