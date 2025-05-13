import os
import geoip2.database
import polars as pl
from geoip2.errors import AddressNotFoundError
from polars import Expr

from core.classifier import IPIDSequence, get_pattern, Pattern
from postproc import GEOLITE_ASN_DB


# Optimized function to parse tuple columns
def parse_tuple_column(col: pl.Expr) -> Expr:
    return col.str.strip_chars("()").str.split(",").list.eval(pl.element().cast(pl.Int64))


# Compute RTT (Round Trip Time)
def compute_rtt(sent: list[int], recv: list[int]) -> list[float]:
    return [(r - s) / 1e6 for s, r in zip(sent, recv)]


# Detect pattern based on IP IDs
def detect_pattern(ip_ids: list[int]) -> str:
    ip_id_sequence = IPIDSequence(ip_ids)
    detected_pattern: Pattern = get_pattern(ip_id_sequence)
    return detected_pattern.value


# Optimized GeoIP ASN retrieval
def get_asn(asn_reader: geoip2.database.Reader, ip: str) -> str:
    try:
        asn_response = asn_reader.asn(ip)
        return str(asn_response.autonomous_system_number)
    except AddressNotFoundError:
        return "None"


def start(result_dir: str):
    probing_csv = os.path.join(result_dir, "probing.csv")
    eval_csv = os.path.join(result_dir, "eval.csv")

    # Open the GeoIP database only once
    asn_reader = geoip2.database.Reader(GEOLITE_ASN_DB)

    lazy_df = (
        pl.read_csv(probing_csv, quote_char='"', ignore_errors=True).lazy()
        .with_columns([
            parse_tuple_column(pl.col("IP_ID_SEQUENCE")).alias("ip_ids"),
            parse_tuple_column(pl.col("SEND_TS_SEQUENCE")).alias("send_ts"),
            parse_tuple_column(pl.col("RECEIVED_TS_SEQUENCE")).alias("recv_ts"),
        ])
        .with_columns([
            pl.struct(["send_ts", "recv_ts"]).map_elements(
                lambda row: compute_rtt(row["send_ts"], row["recv_ts"])
            ).alias("rtts")
        ])
        .with_columns([
            pl.col("rtts").list.eval(pl.element().cast(pl.Float64)).list.mean().alias("AVG_RTT"),
            pl.col("rtts").list.eval(pl.element().cast(pl.Float64)).list.std().alias("STD_RTT"),
            pl.col("ip_ids").map_elements(detect_pattern, return_dtype=pl.Utf8).alias("IP_ID_PATTERN"),
            pl.col("IP").map_elements(lambda ip: get_asn(asn_reader, ip), return_dtype=pl.Utf8).alias("ASN")
        ])
        .select(["IP", "IP_ID_PATTERN", "AVG_RTT", "STD_RTT", "ASN"])
    )

    # Collect and write the result
    lazy_df.collect(streaming=True).write_csv(eval_csv)

    # Close the reader after use
    asn_reader.close()
