import logging
import math
import os
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
    seq_request_count: int
    iface_a: Interface
    iface_b: Interface
    max_rtt: str
    send_mbps: int
    default_send_ip_ids: List[int]
    detect_reflected_ip_ids: bool
    reflection_send_ip_ids: List[int]


def load_config(path: str) -> Config:
    with open(path, 'r') as file:
        data = yaml.safe_load(file)
    data['iface_a'] = Interface(**data['iface_a'])
    data['iface_b'] = Interface(**data['iface_b'])
    return Config(**data)


config = load_config('config.yaml')

# B2B_PROBE_COUNT = config['b2bProbeCount']
# SEQ_PROBE_COUNT = config['seqProbeCount']
# TCP_DST_PORT = config['tcpDstPort']
# DETECT_REFLECTED_IPIDS = config['detectReflectedIpIds']
# REFLECTION_SEND_IPIDS = tuple(config['reflectionSendIpIds'])

MAX_IPID = 65535  # 2^16 - 1

MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IPID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1


def create_logger(file_path):
    def get_logger_name(path):
        if "src" in path.split(os.sep):
            return (
                path.split("src", 1)[-1]
                .lstrip(os.sep)
                .replace(os.sep, ".")
                .replace(".py", "")
            )
        else:
            return os.path.splitext(os.path.basename(path))[0]

    name = get_logger_name(file_path)

    logger = logging.getLogger(name.upper())
    logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # file_handler = logging.FileHandler("app.log")
    # file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler.setFormatter(formatter)
    # file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    # logger.addHandler(file_handler)

    return logger


def log_df(logger, df, sub_headline=""):
    logger.info(f"{headline_str(sub_headline)}\n{df.head(20).to_string(index=False)}")


def headline_str(headline, line_char="="):
    if headline == "":
        return ""
    width = 80
    left_side = (width - len(headline) - 2) // 2
    right_side = width - left_side - len(headline) - 2
    return f"{line_char * left_side}[  {headline}  ]{line_char * right_side}"


def get_percent_str(part, total):
    return f"{part / total * 100:.2f}"
