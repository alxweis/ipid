import os
import time

import geoip2.database
import polars as pl
from geoip2.errors import AddressNotFoundError
from polars import Expr

from core.classifier import IPIDSequence, get_pattern, Pattern
from postproc import GEOLITE_ASN_DB


def parse_tuple_column(col: pl.Expr) -> Expr:
    return col.str.replace_all(r"[()]", "").str.split(",").list.eval(pl.element().cast(pl.Int64))


def compute_rtt(sent: pl.Expr, recv: pl.Expr) -> pl.Expr:
    return (recv - sent) / 1e6


def detect_pattern(ip_ids: list[int]) -> str:
    ip_id_sequence = IPIDSequence(ip_ids)
    detected_pattern: Pattern = get_pattern(ip_id_sequence)
    return detected_pattern.value


def get_asn(asn_reader: geoip2.database.Reader, ip: str) -> str:
    try:
        asn_response = asn_reader.asn(ip)
        return str(asn_response.autonomous_system_number)
    except AddressNotFoundError:
        return "None"


def start(result_dir: str):
    start_time = time.time()

    probing_csv = os.path.join(result_dir, "probing.csv")
    eval_csv = os.path.join(result_dir, "eval.csv")

    asn_reader = geoip2.database.Reader(GEOLITE_ASN_DB)

    lf = (
        pl.scan_csv(probing_csv, ignore_errors=True)
        .with_columns([
            parse_tuple_column(pl.col("IP_ID_SEQUENCE")).alias("ip_ids"),
            parse_tuple_column(pl.col("SEND_TS_SEQUENCE")).alias("send_ts"),
            parse_tuple_column(pl.col("RECEIVED_TS_SEQUENCE")).alias("recv_ts"),
        ])
        .with_columns([
            compute_rtt(pl.col("send_ts"), pl.col("recv_ts")).alias("rtts")
        ])
        .with_columns([
            pl.col("rtts").list.mean().alias("AVG_RTT"),
            pl.col("rtts").list.std().alias("STD_RTT"),
            pl.col("ip_ids").map_elements(detect_pattern, return_dtype=pl.Utf8).alias("IP_ID_PATTERN"),
            pl.col("IP").map_elements(lambda ip: get_asn(asn_reader, ip), return_dtype=pl.Utf8).alias("ASN")
        ])
        .select(["IP", "IP_ID_PATTERN", "AVG_RTT", "STD_RTT", "ASN"])
    )

    lf.sink_csv(eval_csv, float_precision=4)

    asn_reader.close()

    end_time = time.time()
    print(f"Total execution time: {end_time - start_time:.2f} seconds")
