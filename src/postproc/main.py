import io
import multiprocessing as mp
import os
from functools import partial
from typing import List, Tuple, Dict, Any

import geoip2.database
import numpy as np
import pandas as pd
import zstandard as zstd
from geoip2.errors import AddressNotFoundError
from tqdm import tqdm

from core.classifier import IPIDSequence, get_pattern, Pattern
from postproc import GEOLITE_ASN_DB


def detect_pattern(ip_ids: np.ndarray) -> Pattern:
    ip_id_sequence = IPIDSequence(ip_ids)
    detected_pattern: Pattern = get_pattern(ip_id_sequence)
    return detected_pattern


def process_row_optimized(row_data: Dict[str, Any], asn_reader) -> Tuple:
    ip = row_data['IP']
    ip_ids = row_data['IP_ID_SEQUENCE']
    sent_ts = row_data['SENT_TS_SEQUENCE']
    recv_ts = row_data['RECEIVED_TS_SEQUENCE']

    try:
        pattern = detect_pattern(ip_ids).value
        rtts = recv_ts - sent_ts
        avg_rtt = np.round(np.average(rtts)).astype(int)
        std_rtt = np.round(np.std(rtts, ddof=1)).astype(int)

        try:
            asn_response = asn_reader.asn(ip)
            asn = str(asn_response.autonomous_system_number)
        except AddressNotFoundError:
            asn = "None"

        return ip, pattern, avg_rtt, std_rtt, asn
    except Exception:
        return None


def worker_process(rows_batch: List[Dict], asn_db_path: str) -> List:
    asn_reader = geoip2.database.Reader(asn_db_path)
    results = []

    for row_data in rows_batch:
        result = process_row_optimized(row_data, asn_reader)
        if result:
            results.append(result)

    asn_reader.close()
    return results


def prepare_row_data(row) -> Dict[str, Any]:
    ip_ids = np.fromstring(row.IP_ID_SEQUENCE, sep=",", dtype=np.int32)
    sent_ts = np.fromstring(row.SENT_TS_SEQUENCE, sep=",", dtype=np.int64)
    recv_ts = np.fromstring(row.RECEIVED_TS_SEQUENCE, sep=",", dtype=np.int64)

    return {
        'IP': row.IP,
        'IP_ID_SEQUENCE': ip_ids,
        'SENT_TS_SEQUENCE': sent_ts,
        'RECEIVED_TS_SEQUENCE': recv_ts
    }


def count_lines_in_zst(file_path):
    dctx = zstd.ZstdDecompressor()
    with open(file_path, "rb") as f:
        reader = dctx.stream_reader(f)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")
        count = sum(1 for _ in text_reader)
    return count


def start(result_dir: str):
    probing_csv = os.path.join(result_dir, "probing.csv.zst")
    eval_csv = os.path.join(result_dir, "eval.csv.zst")

    num_cpus = mp.cpu_count()
    num_workers = max(1, num_cpus - 1)
    print(f"Verwende {num_workers} CPU-Kerne für die Verarbeitung")

    batch_size = 1000
    chunk_size = batch_size * num_workers

    print(f"Zähle Zeilen in der Eingabedatei...")
    total_rows = count_lines_in_zst(probing_csv)
    print(f"Insgesamt {total_rows} Zeilen zu verarbeiten")

    pool = mp.Pool(processes=num_workers)
    worker_func = partial(worker_process, asn_db_path=GEOLITE_ASN_DB)

    dctx = zstd.ZstdDecompressor()
    cctx = zstd.ZstdCompressor(level=3, threads=2)

    processed_rows = 0
    first_chunk = True

    with open(probing_csv, "rb") as ifh, open(eval_csv, "wb") as ofh:
        reader = dctx.stream_reader(ifh)
        compressed_writer = cctx.stream_writer(ofh)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")
        text_writer = io.TextIOWrapper(compressed_writer, encoding="utf-8")

        progress_bar = tqdm(total=total_rows, unit="rows")

        for chunk_df in pd.read_csv(text_reader, chunksize=chunk_size):
            all_rows = []

            for row in chunk_df.itertuples(index=False):
                try:
                    row_data = prepare_row_data(row)
                    all_rows.append(row_data)
                except Exception:
                    continue

            batches = [all_rows[i:i + batch_size] for i in range(0, len(all_rows), batch_size)]

            all_results = []
            for batch_results in pool.map(worker_func, batches):
                all_results.extend(batch_results)

            if all_results:
                results_df = pd.DataFrame(all_results,
                                          columns=["IP", "IP_ID_PATTERN", "AVG_RTT", "STD_RTT", "ASN"])

                results_df.to_csv(
                    text_writer,
                    header=first_chunk,
                    index=False,
                    lineterminator="\n"
                )
                text_writer.flush()

                current_batch_size = len(chunk_df)
                processed_rows += current_batch_size
                progress_bar.update(current_batch_size)

                first_chunk = False

        progress_bar.close()
        text_writer.detach()
        compressed_writer.flush()
        compressed_writer.close()

    pool.close()
    pool.join()

    print(f"Post-Processing finished: result=[{eval_csv}]")
