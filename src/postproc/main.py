import os
import time

import geoip2.database
import polars as pl
from geoip2.errors import AddressNotFoundError
from polars import Expr

from core.classifier import IPIDSequence, get_pattern, Pattern
from core.utils import compress_file, runtime
from postproc import GEOLITE_ASN_DB


def parse_tuple_column(col: pl.Expr) -> Expr:
    return col.str.split(",").list.eval(pl.element().cast(pl.Int64))


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


def get_continent(country_reader: geoip2.database.Reader, ip: str) -> str:
    try:
        country_response = country_reader.country(ip)
        return str(country_response.continent.name)
    except AddressNotFoundError:
        return "None"


def start(result_dir: str):
    start_time = time.time()

    probing_csv = os.path.join(result_dir, "probing.csv.zst")
    eval_csv = os.path.join(result_dir, "eval.csv.zst")
    eval_tmp = os.path.join(result_dir, "eval.tmp")

    asn_reader = geoip2.database.Reader(GEOLITE_ASN_DB)

    batch_size = 1_000_000
    offset = 0
    first_batch = True

    while True:
        try:
            df = pl.read_csv(probing_csv, skip_rows=offset, n_rows=batch_size, ignore_errors=True)

            if df.height == 0:
                break

            df = df.with_columns([
                parse_tuple_column(pl.col("IP_ID_SEQUENCE")).alias("ip_ids"),
                parse_tuple_column(pl.col("SENT_TS_SEQUENCE")).alias("send_ts"),
                parse_tuple_column(pl.col("RECEIVED_TS_SEQUENCE")).alias("recv_ts"),
            ]).with_columns([
                (pl.col("recv_ts") - pl.col("send_ts")).alias("rtts"),
                pl.col("ip_ids").map_elements(detect_pattern, return_dtype=pl.Utf8).alias("IP_ID_PATTERN"),
                pl.col("IP").map_elements(lambda ip: get_asn(asn_reader, ip), return_dtype=pl.Utf8).alias("ASN")
            ]).with_columns([
                pl.col("rtts").list.mean().cast(pl.Int64).alias("AVG_RTT"),
                pl.col("rtts").list.std().cast(pl.Int64).alias("STD_RTT"),
            ]).select(["IP", "IP_ID_PATTERN", "AVG_RTT", "STD_RTT", "ASN"])

            df.write_csv(eval_tmp, append=not first_batch)
            first_batch = False
            offset += batch_size

        except Exception as e:
            print(f"Error processing chunk starting at row {offset}: {e}")
            break

    asn_reader.close()

    eval_csv = compress_file(eval_tmp, eval_csv)

    print(f"Post-Processing finished: {runtime(start_time)} result=[{eval_csv}]")
