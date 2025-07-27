import csv
import io
import os
import re
import subprocess
import time

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


def run_os_scan(ips_tmp_file: str, targets_os_file: str):
    portscan_output_file = f"{os.path.join(os.path.dirname(ips_tmp_file), "output.xml")}"
    result = subprocess.run([
        "masscan",
        "-iL", ips_tmp_file,
        "-p22,161,445",
        "--rate", "100000",
        "-oX", portscan_output_file
    ], capture_output=True, text=True)

    print("Exit-Code:", result.returncode)
    print("Output:", result.stdout)
    print("Errors:", result.stderr)


def start(targets_path: str):
    start_time = time.time()
    ips_tmp_file = setup(targets_path)
    targets_os_file = os.path.join(targets_path, "targets_os.csv")
    run_os_scan(ips_tmp_file, targets_os_file)
    result_file = cleanup(ips_tmp_file=ips_tmp_file, targets_os_file=targets_os_file)
    print(f"OS-Scan finished: {runtime(start_time)} result=[{result_file}]")


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
