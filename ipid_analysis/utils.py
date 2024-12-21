import logging
import math
import os

import yaml


# region Constants
def load_config(config_file):
    with open(config_file, 'r') as file:
        return yaml.safe_load(file)


ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
config = load_config(os.path.join(ROOT_PATH, "ipid_analysis/config.yaml"))
FAST_PROBE_COUNT = config['fastProbeCount']
SLOW_PROBE_COUNT = config['slowProbeCount']
TCP_DST_PORT = config['tcpDstPort']
DETECT_MIRROR = config['detectMirror']
MIRROR_IPIDS = tuple(config['mirrorIpIds'])
PROBE_COUNT = 20

MAX_IPID = 65535  # 2^16 - 1

MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IPID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1


# endregion


def create_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    return logger


def get_msm(msm_path):
    return os.path.join(ROOT_PATH, "measurements", msm_path)


def get_ip_info(database_name):
    return os.path.join(ROOT_PATH, "ip_info", database_name)


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
