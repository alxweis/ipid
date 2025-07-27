import subprocess
import time
from dataclasses import dataclass
from typing import List

import yaml


@dataclass
class Interface:
    name: str
    ip: str


@dataclass
class Config:
    targets: str
    protocol: List[str]
    record_traffic: bool
    tcp_dst_port: int
    tcp_request_flags: str
    tcp_src_port_offset: int
    udp_dst_port: int
    udp_src_port_offset: int
    b2b_request_count: int
    b2b_request_interval: str
    b2b_retry_count: int
    seq_request_count: int
    seq_retry_count: int
    iface_a: Interface
    iface_b: Interface
    max_rtt: str
    default_send_ip_ids: List[int]
    detect_reflected_ip_ids: bool
    reflection_send_ip_ids: List[int]
    zmap_bandwidth: str
    ip_col_name: str
    ts_ip_col_name: str
    us_ip_col_name: str
    os_col_name: str
    us_os_col_name: str
    ts_os_col_name: str
    ip_id_seq_col_name: str
    sent_ts_seq_col_name: str
    received_ts_seq_col_name: str
    ip_id_pattern_col_name: str
    avg_rtt_col_name: str
    std_rtt_col_name: str
    asn_col_name: str


def load_config(path: str) -> Config:
    with open(path, 'r') as file:
        data = yaml.safe_load(file)
    data['iface_a'] = Interface(**data['iface_a'])
    data['iface_b'] = Interface(**data['iface_b'])
    return Config(**data)


config = load_config('config.yaml')


def seconds_to_str(secs: int) -> str:
    hours, remainder = divmod(int(secs), 3600)
    minutes, seconds = divmod(remainder, 60)

    ts = ""
    if hours > 0:
        ts += f"{hours}h"
    if minutes > 0:
        ts += f"{minutes}m"
    if seconds > 0 or not ts:
        ts += f"{seconds}s"

    return ts


def runtime(start: float) -> str:
    elapsed_seconds = int(time.time() - start)
    ts = seconds_to_str(elapsed_seconds)
    return f"runtime=[{ts}]"


def compress_file(input_file: str, output_file_zst: str = None) -> str:
    if not output_file_zst:
        output_file_zst = input_file + ".zst"
    subprocess.run(["zstd", "-T0", "-f", "--rm", "-o", output_file_zst, input_file], check=True)
    return output_file_zst


def decompress_zst(input_file_zst: str) -> str:
    output_file = input_file_zst.removesuffix(".zst")
    subprocess.run(["zstd", "-d", "-T0", "-f", input_file_zst], check=True)
    return output_file
