import csv
import io
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET

import zstandard as zstd

from core.utils import config, compress_file


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


def run_os_scan(ips_tmp_file: str, targets_os_file: str):
    base_dir = os.path.dirname(ips_tmp_file)

    # region PORT SCANNING
    portscan_output_file = os.path.join(base_dir, "output.xml")
    print(f"Executing masscan for {ips_tmp_file} with output {portscan_output_file}...")
    result = subprocess.run([
        "masscan",
        "-iL", ips_tmp_file,
        "-p22,161,445",
        "--rate", "100000",
        "-oX", portscan_output_file
    ], capture_output=True, text=True)

    print("Exit-Code:", result.returncode)
    print(f"Saved in {portscan_output_file}")
    # endregion

    # region OUTPUT PARSING
    ssh_ips = set()
    snmp_ips = set()
    smb_ips = set()

    for event, elem in ET.iterparse("output.xml", events=("end",)):
        if elem.tag == "host":
            ip = elem.find("address").get("addr")
            for port in elem.find("ports").findall("port"):
                port_id = port.get("portid")
                if port_id == "22":
                    ssh_ips.add(ip)
                elif port_id == "161":
                    snmp_ips.add(ip)
                elif port_id == "445":
                    smb_ips.add(ip)
            elem.clear()

    ssh_ips_file = os.path.join(base_dir, "ssh_ips.txt")
    with open(ssh_ips_file, "w") as f:
        f.writelines(ip + "\n" for ip in ssh_ips)
    print(f"Saved IP addresses for SSH/22 in {ssh_ips_file}")

    snmp_ips_file = os.path.join(base_dir, "snmp_ips.txt")
    with open(snmp_ips_file, "w") as f:
        f.writelines(ip + "\n" for ip in snmp_ips)
    print(f"Saved IP addresses for SNMP/161 in {snmp_ips_file}")

    smb_ips_file = os.path.join(base_dir, "smb_ips.txt")
    with open(smb_ips_file, "w") as f:
        f.writelines(ip + "\n" for ip in smb_ips)
    print(f"Saved IP addresses for SMB/445 in {smb_ips_file}")
    # endregion

    # region BUILD SCANNER
    build_file = os.path.join(base_dir, "main.go")
    executable = os.path.join(base_dir, "scanner")
    subprocess.run(["go", "build", "-o", executable, build_file], check=True)
    # endregion

    # region OS FINGERPRINTING
    snmp_result_file = run_scanner(executable, "snmp", snmp_ips_file)
    ssh_result_file = run_scanner(executable, "ssh", ssh_ips_file)
    smb_result_file = run_scanner(executable, "smb", smb_ips_file)
    # endregion

    print(f"TODO: Join {snmp_result_file}, {ssh_result_file}, {smb_result_file} on IP")


def start(targets_path: str):
    start_time = time.time()
    ips_tmp_file = setup(targets_path)
    targets_os_file = os.path.join(targets_path, "targets_os.csv")
    run_os_scan(ips_tmp_file, targets_os_file)
    # result_file = cleanup(ips_tmp_file=ips_tmp_file, targets_os_file=targets_os_file)
    # print(f"OS-Scan finished: {runtime(start_time)} result=[{result_file}]")


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
