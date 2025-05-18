import io
import os
import time

import geoip2.database
import numpy as np
import pandas as pd
import polars as pl
import zstandard as zstd
from geoip2.errors import AddressNotFoundError
from polars import Expr

from core.classifier import IPIDSequence, get_pattern, Pattern
from core.utils import runtime, seconds_to_str
from postproc import GEOLITE_ASN_DB


def parse_tuple_column(col: pl.Expr) -> Expr:
    return col.str.split(",").list.eval(pl.element().cast(pl.Int64))


def detect_pattern(ip_ids: np.ndarray) -> Pattern:
    ip_id_sequence = IPIDSequence(ip_ids)
    detected_pattern: Pattern = get_pattern(ip_id_sequence)
    return detected_pattern


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


def process_row(row, asn_reader):
    ip = row.IP
    ip_ids = np.fromstring(row.IP_ID_SEQUENCE, sep=",", dtype=int)
    sent_ts = np.fromstring(row.SENT_TS_SEQUENCE, sep=",", dtype=int)
    recv_ts = np.fromstring(row.RECEIVED_TS_SEQUENCE, sep=",", dtype=int)

    pattern = detect_pattern(ip_ids).value
    rtts = recv_ts - sent_ts
    avg_rtt = np.round(np.average(rtts)).astype(int)
    std_rtt = np.round(np.std(rtts, ddof=1)).astype(int)
    asn = get_asn(asn_reader, ip)

    return ip, pattern, avg_rtt, std_rtt, asn


def process_chunk(df, asn_reader, processed_rows, last_log_time, start_proc_time, total_rows):
    results = []

    for row in df.itertuples(index=False):
        try:
            result = process_row(row, asn_reader)
            if result:
                results.append(result)

            processed_rows += 1
            now = time.time()

            if now - last_log_time >= 1.0:
                elapsed_seconds = now - start_proc_time
                rows_per_sec = processed_rows / elapsed_seconds if elapsed_seconds > 0 else 0
                rows_left = total_rows - processed_rows
                est_seconds_left = rows_left / rows_per_sec if rows_per_sec > 0 else 0
                print(f"Processed: rows=[{processed_rows}] rows_per_sec=[{rows_per_sec:.0f}] elapsed_time=[{seconds_to_str(elapsed_seconds)}] estimated_time_left=[{seconds_to_str(est_seconds_left)}]")
                last_log_time = now
        except:
            continue

    return pd.DataFrame(results,
                        columns=["IP", "IP_ID_PATTERN", "AVG_RTT", "STD_RTT", "ASN"]), processed_rows, last_log_time


def count_lines_in_zst(file_path):
    dctx = zstd.ZstdDecompressor()
    with open(file_path, "rb") as f:
        reader = dctx.stream_reader(f)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")
        count = 0
        for _ in text_reader:
            count += 1
    return count


def start(result_dir: str):
    probing_csv = os.path.join(result_dir, "probing.csv.zst")
    eval_csv = os.path.join(result_dir, "eval.csv.zst")

    total_rows = count_lines_in_zst(probing_csv)

    start_time = time.time()

    asn_reader = geoip2.database.Reader(GEOLITE_ASN_DB)

    dctx = zstd.ZstdDecompressor()
    cctx = zstd.ZstdCompressor()
    chunk_size = 100_000

    with open(probing_csv, "rb") as ifh, open(eval_csv, "wb") as ofh:
        reader = dctx.stream_reader(ifh)
        compressed_writer = cctx.stream_writer(ofh)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")
        text_writer = io.TextIOWrapper(compressed_writer, encoding="utf-8")

        first_chunk = True
        processed_rows = 0
        last_log_time = time.time()
        start_proc_time = last_log_time

        for chunk in pd.read_csv(text_reader, chunksize=chunk_size):
            processed, processed_rows, last_log_time = process_chunk(chunk, asn_reader, processed_rows, last_log_time,
                                                                     start_proc_time, total_rows)
            processed.to_csv(
                text_writer,
                header=first_chunk,
                index=False,
                lineterminator="\n"
            )
            text_writer.flush()
            first_chunk = False

        text_writer.detach()
        compressed_writer.flush()
        compressed_writer.close()

    asn_reader.close()

    print(f"Post-Processing finished: {runtime(start_time)} result=[{eval_csv}]")
