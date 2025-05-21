import collections
import io
import multiprocessing as mp
import os
import os.path
import time
from collections import Counter
from functools import partial

import geoip2.database
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import polars as pl
import seaborn as sns
import zstandard as zstd
from geoip2.errors import AddressNotFoundError
from tqdm import tqdm

from core.classifier import IPIDSequence, Pattern
from core.utils import config, runtime
from postproc import GEOLITE_COUNTRY_DB
from postproc.main import count_lines_in_zst


def plot_response_rate(targets_csv: str, ts_type: str):
    ts_col_name = None
    if ts_type == "ip":
        ts_col_name = config.ts_ip_col_name
    elif ts_type == "os":
        ts_col_name = config.ts_os_col_name

    df = (
        pl.scan_csv(targets_csv)
        .select([ts_col_name, "IP"])
        .group_by(ts_col_name)
        .agg(pl.count("IP").alias("count"))
        .sort(ts_col_name)
        .collect()
    )

    plt.figure(figsize=(10, 6))

    start_time = df[ts_col_name][0]
    end_time = df[ts_col_name][-1]
    time_diff = end_time - start_time

    if time_diff > 3600:
        unit = 3600.0
        label = "h"
    elif time_diff > 60:
        unit = 60.0
        label = "m"
    else:
        unit = 1.0
        label = "s"

    time_values = (df[ts_col_name] - start_time) / unit
    plt.plot(time_values, df["count"], alpha=0.3, linewidth=0.7, color='#1f77b4')
    plt.plot(time_values, df["count"], marker="o", linestyle="None", markersize=3, alpha=1, color='#1f77b4')
    plt.xlabel(f"Time (in {label}, 1s interval)", fontsize=18)
    plt.xticks(fontsize=16)
    plt.ylabel("Identified Targets", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, linestyle="--", alpha=0.6)
    # plt.title(f"Response Rate for {ts_type.upper()}-Scan", fontsize=18)
    plt.tight_layout()
    output_dir = os.path.join(os.path.dirname(targets_csv), "analysis_targets")
    plt.savefig(os.path.join(output_dir, f"response_rate_{ts_type}_scan.pdf"), bbox_inches="tight")
    plt.close()


class ProcessingParams:
    def __init__(self, num_workers: int, batch_size: int, total_rows: int, probing_csv: str, eval_csv: str,
                 output_dir: str):
        self.num_workers = num_workers
        self.batch_size = batch_size
        self.total_rows = total_rows
        self.probing_csv = probing_csv
        self.eval_csv = eval_csv
        self.output_dir = output_dir

    def chunk_size(self):
        return self.batch_size * self.num_workers


def count_pattern(batch: pd.DataFrame) -> collections.Counter:
    return Counter(batch["IP_ID_PATTERN"])


def plot_pattern_distribution(params: ProcessingParams):
    pattern_counter = Counter()
    pool = mp.Pool(processes=params.num_workers)
    dctx = zstd.ZstdDecompressor()

    with open(params.eval_csv, "rb") as f:
        reader = dctx.stream_reader(f)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")

        progress_bar = tqdm(total=params.total_rows, unit="rows")

        for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size()):
            batches = [chunk_df[i:i + params.batch_size] for i in range(0, len(chunk_df), params.batch_size)]

            for batch_pattern_counter in pool.map(count_pattern, batches):
                pattern_counter.update(batch_pattern_counter)

            progress_bar.update(len(chunk_df))

        progress_bar.close()

    pool.close()
    pool.join()

    total = sum(pattern_counter.values())
    relative = {k: (v / total) * 100 for k, v in pattern_counter.items()}
    df = pd.DataFrame(list(relative.items()), columns=['class', 'percentage'])

    full_order = [p.value for p in Pattern]
    order = [p for p in full_order if p in df["class"].values]

    # Plot
    plt.figure(figsize=(7, 7))
    ax = sns.barplot(
        x="class",
        y="percentage",
        data=df,
        order=order
    )
    for container in ax.containers:
        ax.bar_label(container, fmt='%.1f%%', label_type='edge', padding=3, fontsize=16)
    plt.xlabel("Class", fontsize=18)
    plt.xticks(rotation=60, fontsize=16)
    plt.ylabel("Percentage (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0, top=100)
    plt.grid(True, axis="y", linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(params.output_dir, "pattern_distribution.pdf"), bbox_inches="tight")
    plt.close()


def calc_time_between_requests(rows_batch: list[np.ndarray]) -> list[np.ndarray]:
    results = []

    for row_data in rows_batch:
        results.append(np.diff(row_data) / 1e3)

    return results


def plot_time_between_requests(params: ProcessingParams):
    time_between_requests = []
    pool = mp.Pool(processes=params.num_workers)
    dctx = zstd.ZstdDecompressor()

    def prepare_row_data(row) -> np.ndarray:
        return np.fromstring(row.SENT_TS_SEQUENCE, sep=",", dtype=np.int64)

    with open(params.probing_csv, "rb") as f:
        reader = dctx.stream_reader(f)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")

        progress_bar = tqdm(total=params.total_rows, unit="rows")

        for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size()):
            all_rows = []

            for row in chunk_df.itertuples(index=False):
                try:
                    row_data = prepare_row_data(row)
                    all_rows.append(row_data)
                except Exception:
                    continue

            batches = [all_rows[i:i + params.batch_size] for i in range(0, len(all_rows), params.batch_size)]

            for deltas in pool.map(calc_time_between_requests, batches):
                time_between_requests.extend(deltas)

            progress_bar.update(len(chunk_df))

        progress_bar.close()

    pool.close()
    pool.join()

    # Plot
    deltas = np.array(time_between_requests, dtype=np.float32)
    q = np.percentile(deltas, 99.9)
    deltas_cut = deltas[deltas <= q]

    plt.figure(figsize=(10, 6))
    sns.histplot(deltas_cut, bins=100, stat="percent")
    plt.xlabel("Time between Requests (ms)", fontsize=18)
    plt.xticks(fontsize=16)
    plt.xlim(left=0)
    plt.ylabel("Relative Frequency (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="both", linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(params.output_dir, "time_between_requests.pdf"), bbox_inches="tight")
    plt.close()


def get_continent_rtts(batch: pd.DataFrame) -> dict[str, list[float]]:
    country_reader = geoip2.database.Reader(GEOLITE_COUNTRY_DB)
    continent_to_rtts = {}

    for _, row in batch.iterrows():
        ip = row["IP"]
        avg_rtt = row["AVG_RTT"] / 1e3
        try:
            continent = str(country_reader.country(ip).continent.name)
        except AddressNotFoundError:
            continent = "None"
        continent_to_rtts.setdefault(continent, []).append(avg_rtt)

    country_reader.close()
    return continent_to_rtts


def plot_avg_rtt_per_continent(params: ProcessingParams):
    continent_to_rtts = {}
    pool = mp.Pool(processes=params.num_workers)
    dctx = zstd.ZstdDecompressor()
    total_rtt_count = 0

    with open(params.eval_csv, "rb") as f:
        reader = dctx.stream_reader(f)
        text_reader = io.TextIOWrapper(reader, encoding="utf-8")

        progress_bar = tqdm(total=params.total_rows, unit="rows")

        for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size()):
            batches = [chunk_df[i:i + params.batch_size] for i in range(0, len(chunk_df), params.batch_size)]

            for batch_continent_to_rtts in pool.map(get_continent_rtts, batches):
                for continent, rtts in batch_continent_to_rtts.items():
                    total_rtt_count += len(rtts)
                    continent_to_rtts.setdefault(continent, []).extend(rtts)

            progress_bar.update(len(chunk_df))

        progress_bar.close()

    pool.close()
    pool.join()

    # Plot
    continent_to_rtts_numpy = {}
    continents = {}
    total_value_sum = 5_000_000
    for continent, rtts in continent_to_rtts.items():
        arr = np.array(rtts, dtype=np.float32)
        q = np.percentile(arr, 99)
        arr_cut = arr[arr <= q]

        rtt_count = len(arr_cut)
        if rtt_count < total_rtt_count * 0.01:
            continue

        preferred_sample_size = int(round(total_value_sum * rtt_count / float(total_rtt_count)))
        sample_size = min(preferred_sample_size, rtt_count)
        arr_sampled = np.random.choice(arr_cut, size=sample_size, replace=False)
        continent_to_rtts_numpy[continent] = arr_sampled
        continents[continent] = rtt_count

    order = sorted(continents, key=continents.get, reverse=True)

    df = pd.DataFrame([
        {"continent": cont, "rtts": val}
        for cont, arr in continent_to_rtts_numpy.items()
        for val in arr
    ])

    plt.figure(figsize=(10, 6))
    sns.violinplot(data=df, x="continent", y="rtts", density_norm="count", inner="quartile", order=order)
    plt.xlabel("")
    plt.xticks(rotation=30, fontsize=16)
    plt.ylabel("Average RTT (ms)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="y", linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(params.output_dir, "rtt_per_continent.pdf"), bbox_inches="tight")
    plt.close()


def get_increments_for_pattern(rows_batch: list[np.ndarray], pattern: Pattern) -> list[np.ndarray]:
    results = []

    for row_data in rows_batch:
        ip_id_sequence = IPIDSequence(row_data)
        if pattern in {Pattern.LOCAL_EQ1, Pattern.LOCAL_GE1}:
            results.append(np.concatenate([ip_id_sequence.even.increments, ip_id_sequence.odd.increments]))
        else:
            results.append(ip_id_sequence.full.increments)

    return results


def plot_increment_distribution(params: ProcessingParams, pattern: Pattern):
    increments = []
    pool = mp.Pool(processes=params.num_workers)
    probing_dctx = zstd.ZstdDecompressor()
    eval_dctx = zstd.ZstdDecompressor()
    worker_func = partial(get_increments_for_pattern, pattern=pattern)

    def prepare_row_data(row) -> np.ndarray:
        return np.fromstring(row.IP_ID_SEQUENCE, sep=",", dtype=np.int32)

    with open(params.probing_csv, "rb") as probing_f, open(params.eval_csv, "rb") as eval_f:
        probing_reader = probing_dctx.stream_reader(probing_f)
        eval_reader = eval_dctx.stream_reader(eval_f)
        probing_text_reader = io.TextIOWrapper(probing_reader, encoding="utf-8")
        eval_text_reader = io.TextIOWrapper(eval_reader, encoding="utf-8")

        progress_bar = tqdm(total=params.total_rows, unit="rows")

        probing_iter = pd.read_csv(probing_text_reader, chunksize=params.chunk_size())
        eval_iter = pd.read_csv(eval_text_reader, chunksize=params.chunk_size())

        for probing_chunk_df in probing_iter:
            eval_chunk_df = next(eval_iter)

            assert probing_chunk_df["IP"].equals(eval_chunk_df["IP"])
            chunk_df = pd.concat([probing_chunk_df, eval_chunk_df.drop(columns="IP")], axis=1)
            chunk_length = len(chunk_df)
            chunk_df = chunk_df[chunk_df["IP_ID_PATTERN"] == pattern.value]

            all_rows = []
            for row in chunk_df.itertuples(index=False):
                try:
                    assert row.IP_ID_PATTERN == pattern.value
                    row_data = prepare_row_data(row)
                    all_rows.append(row_data)
                except Exception:
                    continue

            batches = [all_rows[i:i + params.batch_size] for i in range(0, len(all_rows), params.batch_size)]

            for batch_increments_for_pattern in pool.map(worker_func, batches):
                increments.extend(batch_increments_for_pattern)

            progress_bar.update(chunk_length)

        progress_bar.close()

    pool.close()
    pool.join()

    # Plot
    increments_numpy = np.array(increments, dtype=np.int32)
    q = np.percentile(increments_numpy, 99)
    increments_cut = increments_numpy[increments_numpy <= q]
    sample_size = min(10_000_000, len(increments_cut))
    increments_sampled = np.random.choice(increments_cut, size=sample_size, replace=False)

    plt.figure(figsize=(10, 6))
    sns.histplot(increments_sampled, bins=100, stat="percent")
    plt.xlabel("IP-ID Increment", fontsize=18)
    plt.xticks(fontsize=16)
    plt.xlim(left=0)
    plt.ylabel("Relative Frequency (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="both", linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(params.output_dir, f"inc_distribution_{pattern.value.lower().replace(" ", "")}.pdf"),
                bbox_inches="tight")
    plt.close()


def start(result_dir: str):
    start_time = time.time()

    eval_csv = os.path.join(result_dir, "eval.csv.zst")
    probing_csv = os.path.join(result_dir, "probing.csv.zst")

    plot_output_dir = os.path.join(result_dir, "analysis")
    os.makedirs(plot_output_dir, exist_ok=True)

    num_cpus = mp.cpu_count()
    num_workers = max(1, num_cpus - 1)
    print(f"Using {num_workers} CPU cores for processing")

    batch_size = 5000

    print(f"Counting lines of probing_csv file...")
    total_rows_probing_csv = count_lines_in_zst(probing_csv)
    print(f"Total {total_rows_probing_csv} rows to process for probing_csv")

    print(f"Counting lines of eval_csv file...")
    total_rows_eval_csv = count_lines_in_zst(eval_csv)
    print(f"Total {total_rows_eval_csv} rows to process for eval_csv")

    assert total_rows_eval_csv == total_rows_probing_csv, "probing_csv and eval_csv should have same line count!"

    params = ProcessingParams(num_workers=num_workers, batch_size=batch_size, total_rows=total_rows_probing_csv,
                              probing_csv=probing_csv, eval_csv=eval_csv, output_dir=plot_output_dir)

    plot_pattern_distribution(params)
    plot_time_between_requests(params)
    plot_avg_rtt_per_continent(params)
    plot_increment_distribution(params, Pattern.GLOBAL)
    plot_increment_distribution(params, Pattern.LOCAL_GE1)
    plot_increment_distribution(params, Pattern.RANDOM)

    print(f"Analysis finished: {runtime(start_time)} result=[{plot_output_dir}]")
