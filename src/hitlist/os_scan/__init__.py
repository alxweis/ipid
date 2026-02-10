import csv
import io
import json
import os
import re
import subprocess
import sys
import time

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


def run_port_scan(ips_tmp_file: str) -> tuple:
    base_dir = os.path.dirname(ips_tmp_file)
    output_file = os.path.join(base_dir, "output.jsonl")
    db_file = os.path.join(base_dir, "scan.duckdb")

    print(f"Starting Port-Scan for {ips_tmp_file}...")

    # process = subprocess.Popen(
    #     [
    #         "masscan",
    #         "-iL", ips_tmp_file,
    #         "-p22,161,445,80,53",
    #         "--rate", "30000",
    #         "-oJ", output_file
    #     ],
    #     stdout=subprocess.PIPE,
    #     stderr=subprocess.STDOUT,
    #     universal_newlines=True,
    #     bufsize=1
    # )
    #
    # for line in process.stdout:
    #     print(line.strip())
    #
    # process.wait()
    print(f"Port-Scan finished: result={output_file}")

    con = duckdb.connect(db_file)
    con.execute("SET memory_limit = '1.5GB'")
    con.execute(f"SET temp_directory = '{base_dir}'")

    con.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            ip VARCHAR,
            port INTEGER
        )
    """)

    con.execute(f"""
        INSERT INTO scan_results
        SELECT
            ip,
            CAST(p.port AS INTEGER) AS port
        FROM read_json(
            '{output_file}',
            columns = {{ip: 'VARCHAR', ports: 'STRUCT(port INTEGER)[]'}},
            format = 'newline_delimited',
            ignore_errors = true
        ),
        UNNEST(ports) AS t(p)
    """)

    con.execute("CREATE INDEX IF NOT EXISTS idx_port ON scan_results(port)")

    services = {
        22: "ssh",
        161: "snmp",
        445: "smb",
        80: "http",
        53: "dns"
    }

    service_files = {}

    for port, service in services.items():
        filename = os.path.join(base_dir, f"{service}_ips.txt")

        row_count = con.execute(
            f"SELECT COUNT(DISTINCT ip) FROM scan_results WHERE port = {port}"
        ).fetchone()[0]

        if row_count > 0:
            con.execute(f"""
                COPY (
                    SELECT DISTINCT ip
                    FROM scan_results
                    WHERE port = {port}
                )
                TO '{filename}' (FORMAT CSV, HEADER false)
            """)
            print(f"Saved {row_count} IPs for {service.upper()} -> {filename}")
            service_files[service] = filename
        else:
            service_files[service] = None

    con.close()

    return (
        service_files["snmp"],
        service_files["ssh"],
        service_files["smb"],
        service_files["http"],
        service_files["dns"]
    )


def ensure_header(output_file: str, mode: str):
    if os.path.getsize(output_file) == 0:
        con = duckdb.connect()
        query = f"""
        COPY (
            SELECT NULL AS IP, NULL AS {mode.upper()}_OS_INFO
            WHERE FALSE
        ) TO '{output_file}' (FORMAT CSV, COMPRESSION ZSTD, HEADER);
        """
        con.execute(query)
        con.close()


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
    ensure_header(output_file, mode)
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
                                server_str = server_str.replace(",", " ")
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

            return_code = zdns_process.wait()
            if return_code != 0:
                print(f"Warning: zdns exited with code {return_code}", file=sys.stderr)

        print(f"Scan complete. Identified OS for {result_count} out of {processed_count} IPs.")
        return output_file

    except Exception as e:
        print(f"Error running zdns: {str(e)}", file=sys.stderr)


def run_os_scan(ips_tmp_file: str, targets_os_file: str):
    snmp_ips_file, ssh_ips_file, smb_ips_file, http_ips_file, dns_ips_file = run_port_scan(ips_tmp_file)

    go_file = os.path.join(os.path.dirname(__file__), "main.go")
    executable = os.path.join(os.path.dirname(__file__), "scanner")
    subprocess.run(["go", "build", "-o", executable, go_file], check=True, cwd=os.path.dirname(__file__))

    snmp_result_file = run_scanner(executable, "snmp", snmp_ips_file)
    ssh_result_file = run_scanner(executable, "ssh", ssh_ips_file)
    smb_result_file = run_scanner(executable, "smb", smb_ips_file)
    http_result_file = run_http_scan(http_ips_file)
    dns_result_file = run_dns_scan(dns_ips_file)

    con = duckdb.connect()
    query = f"""
    COPY (
        SELECT
            COALESCE(snmp.IP, ssh.IP, smb.IP, http.IP, dns.IP) AS IP,

            COALESCE(
                REGEXP_EXTRACT(
                   CONCAT_WS(' ',
                      COALESCE(snmp.SNMP_OS_INFO, ''),
                      COALESCE(smb.SMB_OS_INFO, ''),
                      COALESCE(ssh.SSH_OS_INFO, ''),
                      COALESCE(http.HTTP_OS_INFO, ''),
                      COALESCE(dns.DNS_OS_INFO, '')
                   ),
                   '(?i)(' || '{os_pattern_str}' || ')'
                ),
                ''
            ) AS OS,

            COALESCE(snmp.SNMP_OS_INFO, '')   AS SNMP_OS_INFO,
            COALESCE(smb.SMB_OS_INFO, '')     AS SMB_OS_INFO,
            COALESCE(ssh.SSH_OS_INFO, '')     AS SSH_OS_INFO,
            COALESCE(http.HTTP_OS_INFO, '')   AS HTTP_OS_INFO,
            COALESCE(dns.DNS_OS_INFO, '')     AS DNS_OS_INFO

        FROM read_csv_auto('{snmp_result_file}', ignore_errors=True) snmp
        FULL OUTER JOIN read_csv_auto('{ssh_result_file}') ssh USING (IP)
        FULL OUTER JOIN read_csv_auto('{smb_result_file}') smb USING (IP)
        FULL OUTER JOIN read_csv_auto('{http_result_file}') http USING (IP)
        FULL OUTER JOIN read_csv_auto('{dns_result_file}') dns USING (IP)
    ) TO '{targets_os_file}' (FORMAT CSV, COMPRESSION ZSTD, HEADER);
    """
    con.execute(query)

    # Cleanup # TODO Add back later
    # os.remove(snmp_ips_file)
    # os.remove(ssh_ips_file)
    # os.remove(http_ips_file)
    # os.remove(dns_ips_file)
    #
    # os.remove(snmp_result_file)
    # os.remove(ssh_result_file)
    # os.remove(http_result_file)
    # os.remove(dns_result_file)


def start(targets_path: str):
    start_time = time.time()
    ips_tmp_file = setup(targets_path)
    targets_os_file = os.path.join(targets_path, "targets_os.csv.zst")
    run_os_scan(ips_tmp_file, targets_os_file)
    os.remove(ips_tmp_file)
    print(f"OS-Scan finished: {runtime(start_time)} result=[{targets_os_file}]")


router = ["openwrt", "lede", "dd-wrt", "ddwrt", "wrt", "vyos", "vyatta", "pfsense",
          "routeros", "mikrotik", "edgeos", "airos", "unifi", "ubiquiti",
          "junos", "juniper", "cisco ios", "ios-xe", "nx-os", "ios", "cisco",
          "fortios", "fortinet", "forti", "sonicos", "sonicwall", "sonic",
          "arubaos", "aruba", "draytek", "drayos", "vigor", "dray",
          "zynos", "zyxel", "vrp", "gaia", "huawei", "router"]

end_device = ["ubuntu", "centos", "debian", "redhat", "ret hat", "rhel", "fedora", "gentoo",
              "opensuse", "euleros", "zorin", "linux", "windows server", "windows",
              "win", "microsoft", "lanman", "freebsd", "openbsd", "netbsd", "bsd",
              "macos", "darwin", "solaris"]

soft_palette = [
    "#FFE866",  # soft yellow
    "#66E0E0",  # aqua
    "#FF8080",  # soft red
    "#6FB8FF",  # sky blue
    "#6EE66E",  # soft green
    "#B580FF",  # violet
    "#FFB266",  # soft orange
    "#99CCFF",  # pastel azure
    "#99FFCC",  # pastel turquoise
    "#FFC19C",  # peach
    "#FFD28A",  # warm sand
    "#FF99CC",  # pastel pink
    "#CCFF99",  # pastel lime
    "#C4A2FF",  # pastel purple
    "#CFA6FF",  # lavender
    "#A2C1FF",  # pastel bluish
    "#A9A9FF",  # purple-blue pastel
    "#A2FFC1",  # light mint
    "#99D6FF",  # light blue
    "#6EE66E",  # soft green
    "#6FD1C8",  # teal pastel
    "#FFCC99",  # pastel apricot
    "#FFA6A6",  # light rose
    "#CC99FF",  # soft purple-pink
    "#99FFAA",  # lime mint
    "#FF99AA",  # salmon pastel
    "#AAFF99",  # yellow-green mint
    "#FFAA99"  # coral pastel
    "#9DE6B8",  # mint
]
# random.seed(44)
# random.shuffle(soft_palette)


fallback_color = "#A0A0A0"

os_groups = {
    "Ubuntu/Debian": (["ubuntu", "debian"], soft_palette[0]),
    "CentOS": (["centos"], soft_palette[1]),
    "RHEL": (["redhat", "ret hat", "rhel"], soft_palette[2]),
    "Fedora": (["fedora"], soft_palette[3]),
    "Windows": (["windows server", "windows", "win", "microsoft", "lanman"], soft_palette[4]),
    "FreeBSD": (["freebsd"], soft_palette[5]),
    "OpenBSD": (["openbsd"], soft_palette[6]),
    "MacOS": (["macos", "darwin"], soft_palette[7]),
    "Huawei VRP": (["vrp", "huawei"], soft_palette[8]),
    "Mikrotik RouterOS": (["routeros", "mikrotik"], soft_palette[9]),
    "Juniper JunOS": (["junos", "juniper"], soft_palette[10]),
    "Cisco IOS": (["cisco ios", "ios-xe", "ios", "cisco"], soft_palette[11]),
    "Cisco NX-OS": (["nx-os"], soft_palette[12]),
    "Fortinet FortiOS": (["fortios", "fortinet", "forti"], soft_palette[13]),
    "SonicOS": (["sonicos", "sonicwall", "sonic"], soft_palette[14]),
    "ArubaOS": (["arubaos", "aruba"], soft_palette[15]),
    "DrayOS": (["draytek", "drayos", "vigor", "dray"], soft_palette[16]),
    "ZynOS": (["zynos", "zyxel"], soft_palette[17]),
}

pretty_oses = {
    # Groups
    **{group: group for group in os_groups},

    # Raw OSes
    "gentoo": "Gentoo",
    "opensuse": "OpenSUSE",
    "euleros": "EulerOS",
    "zorin": "Zorin",
    "linux": "Linux",
    "netbsd": "NetBSD",
    "bsd": "BSD",
    "solaris": "Solaris",
    "fritz": "FritzOS",
    "rasp": "Raspbian",
    "openwrt": "OpenWRT",
    "lede": "LEDE",
    "dd-wrt": "DD-WRT",
    "ddwrt": "DD-WRT",
    "wrt": "WRT",
    "vyos": "VyOS",
    "vyatta": "Vyatta",
    "pfsense": "pfSense",
    "edgeos": "EdgeOS",
    "airos": "AirOS",
    "unifi": "UniFi",
    "ubiquiti": "Ubiquiti",
    "aix": "AIX",
    "hp-ux": "HP-UX",
    "hpux": "HP-UX",
    "zos": "z/OS",
    "openvms": "OpenVMS",
    "vms": "VMS",
    "busybox": "BusyBox",
    "vxworks": "VxWorks",
    "qnx": "QNX",
    "freertos": "FreeRTOS",
    "openembedded": "OpenEmbedded",
    "yocto": "Yocto",
    "utm": "UTM",
    "gaia": "Gaia",
    "router": "Router",
    "server": "Server",
}

oses = [
    "ubuntu", "centos", "debian", "redhat", "ret hat", "rhel", "fedora", "gentoo", "opensuse", "euleros", "zorin",
    "linux", "windows server", "windows", "win", "microsoft", "lanman", "freebsd", "openbsd", "netbsd", "bsd", "macos",
    "darwin", "solaris",
    "fritz", "rasp", "openwrt", "lede", "dd-wrt", "ddwrt", "wrt", "vyos", "vyatta", "pfsense", "routeros", "mikrotik",
    "edgeos", "airos", "unifi", "ubiquiti", "junos", "juniper", "cisco ios", "ios-xe", "nx-os", "ios", "cisco",
    "fortios", "fortinet", "forti", "sonicos", "sonicwall", "sonic", "arubaos", "aruba", "draytek", "drayos", "vigor",
    "dray", "zynos", "zyxel", "aix", "hp-ux", "hpux", "zos", "openvms", "vms", "vrp", "busybox", "vxworks",
    "qnx", "freertos", "openembedded", "yocto", "utm", "gaia", "huawei", "router", "server"
]
os_pattern = re.compile("|".join(oses), re.IGNORECASE)
os_pattern_str = "|".join(re.escape(x) for x in oses)
