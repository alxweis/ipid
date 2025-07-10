import collections
import glob
import io
import math
import multiprocessing as mp
import os
import os.path
import time
from collections import Counter
from functools import partial

import duckdb
import geoip2.database
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import zstandard as zstd
from geoip2.errors import AddressNotFoundError
from tqdm import tqdm

from core import EXP_INTERSECTIONS
from core.classifier import IPIDSequence, Pattern, p_value, get_clusters
from core.utils import config, runtime
from postproc import GEOLITE_COUNTRY_DB
from postproc.main import count_lines_in_zst


def plot_response_rate(targets_csv: str, ts_type: str):
    ts_col_name = None
    if ts_type == "ip":
        ts_col_name = config.ts_ip_col_name
    elif ts_type == "os":
        ts_col_name = config.ts_os_col_name

    conn = duckdb.connect()

    try:
        # Query 1: Aggregierte Daten
        agg_query = f"""
        SELECT {ts_col_name}, COUNT(IP) as count
        FROM read_csv_auto('{targets_csv}', compression='zstd')
        GROUP BY {ts_col_name}
        ORDER BY {ts_col_name}
        """

        # Query 2: Min/Max für Zeitbereich (sehr schnell mit Index-Scan)
        minmax_query = f"""
        SELECT MIN({ts_col_name}) as start_time, MAX({ts_col_name}) as end_time
        FROM read_csv_auto('{targets_csv}', compression='zstd')
        """

        # Beide Queries ausführen
        agg_result = conn.execute(agg_query).fetchnumpy()
        minmax_result = conn.execute(minmax_query).fetchone()

        timestamps = agg_result[ts_col_name]
        counts = agg_result['count']
        start_time, end_time = minmax_result

    finally:
        conn.close()

    plt.figure(figsize=(10, 6))

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

    time_values = (timestamps - start_time) / unit

    plt.plot(time_values, counts, alpha=0.3, linewidth=0.7, color='#1f77b4')
    plt.plot(time_values, counts, marker="o", linestyle="None", markersize=3, alpha=1, color='#1f77b4')
    plt.xlabel(f"Time (in {label}, 1s interval)", fontsize=18)
    plt.xticks(fontsize=16)
    plt.ylabel("Identified Targets", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()

    output_dir = os.path.join(os.path.dirname(targets_csv), "analysis", f"response_rate_{ts_type}_scan")
    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(os.path.join(output_dir, f"plot.pdf"), bbox_inches="tight")
    plt.close()


def calc_intersections(target_csvs: list[str], on: str):
    if len(target_csvs) < 2:
        print("❌ At least 2 files required for intersection")
        return

    conn = duckdb.connect()

    # List to store all output lines
    output_lines = []

    def log_output(text):
        print(text)
        output_lines.append(text)

    log_output("=" * 80)
    log_output(f"🔍 INTERSECTION ANALYSIS - Column: {on}")
    log_output("=" * 80)

    # 1. Individual file statistics
    file_stats = {}
    temp_tables = []

    for i, file_path in enumerate(target_csvs):
        table_name = f"file_{i}"
        temp_tables.append(table_name)

        log_output(f"\n📁 File: {file_path}")
        log_output("-" * 50)

        try:
            # Create temporary table
            conn.execute(f"""
                CREATE TEMP TABLE {table_name} AS 
                SELECT DISTINCT {on} 
                FROM read_csv_auto('{file_path}', compression='zstd')
                WHERE {on} IS NOT NULL
            """)

            # Statistics for individual file
            total_values = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            sample_values = conn.execute(f"SELECT {on} FROM {table_name} LIMIT 5").fetchall()

            file_stats[file_path] = total_values

            log_output(f"   Unique values: {total_values:,}")
            log_output(f"   Sample values: {', '.join([str(val[0]) for val in sample_values[:3]])}")

        except Exception as e:
            log_output(f"   ❌ Error reading file: {e}")
            return

    # 2. Pairwise intersections
    log_output(f"\n🔗 PAIRWISE INTERSECTIONS")
    log_output("-" * 50)

    for i in range(len(temp_tables)):
        for j in range(i + 1, len(temp_tables)):
            file1 = target_csvs[i]
            file2 = target_csvs[j]

            intersection_count = conn.execute(f"""
                SELECT COUNT(*) FROM (
                    SELECT {on} FROM {temp_tables[i]}
                    INTERSECT
                    SELECT {on} FROM {temp_tables[j]}
                )
            """).fetchone()[0]

            percentage1 = (intersection_count / file_stats[file1]) * 100 if file_stats[file1] > 0 else 0
            percentage2 = (intersection_count / file_stats[file2]) * 100 if file_stats[file2] > 0 else 0

            log_output(f"   {file1} ∩ {file2}:")
            log_output(f"     Common values: {intersection_count:,}")
            log_output(f"     Percentage of {file1}: {percentage1:.1f}%")
            log_output(f"     Percentage of {file2}: {percentage2:.1f}%")

    # 3. Complete intersection of all files
    log_output(f"\n🎯 COMPLETE INTERSECTION (all {len(target_csvs)} files)")
    log_output("-" * 60)

    # Dynamic intersection across all tables
    intersect_query = f"SELECT {on} FROM {temp_tables[0]}"
    for table in temp_tables[1:]:
        intersect_query += f" INTERSECT SELECT {on} FROM {table}"

    # Calculate intersection
    intersection_result = conn.execute(f"""
        WITH intersection AS ({intersect_query})
        SELECT COUNT(*) as total_count, array_agg({on}) as value_list
        FROM intersection
    """).fetchone()

    total_intersection = intersection_result[0]
    intersection_values = intersection_result[1] if intersection_result[1] else []

    log_output(f"   Common values in ALL files: {total_intersection:,}")

    if total_intersection > 0:
        log_output(f"   Sample common values:")
        for value in intersection_values[:10]:  # Show first 10 values
            log_output(f"     • {value}")

        if total_intersection > 10:
            log_output(f"     ... and {total_intersection - 10} more")

    # 4. Percentage overlap per file
    log_output(f"\n📊 OVERLAP PERCENTAGE PER FILE")
    log_output("-" * 40)

    for i, file_path in enumerate(target_csvs):
        total_in_file = file_stats[file_path]
        percentage = (total_intersection / total_in_file) * 100 if total_in_file > 0 else 0

        log_output(f"   {file_path}:")
        log_output(f"     {total_intersection:,} of {total_in_file:,} values ({percentage:.1f}%)")
        log_output(f"     {'█' * int(percentage / 5)}{' ' * (20 - int(percentage / 5))} {percentage:.1f}%")

    # 5. Union (all unique values)
    union_query = f"SELECT {on} FROM {temp_tables[0]}"
    for table in temp_tables[1:]:
        union_query += f" UNION SELECT {on} FROM {table}"

    total_unique = conn.execute(f"""
        WITH all_values AS ({union_query})
        SELECT COUNT(*) FROM all_values
    """).fetchone()[0]

    log_output(f"\n🌐 OVERALL STATISTICS")
    log_output("-" * 30)
    log_output(f"   Total unique values: {total_unique:,}")
    log_output(f"   Common values: {total_intersection:,}")
    log_output(f"   Overlap percentage: {(total_intersection / total_unique) * 100:.1f}%")

    # 6. Summary table
    log_output(f"\n📋 SUMMARY TABLE")
    log_output("-" * 50)
    log_output(f"{'File':<30} {'Unique Values':<15} {'Common %':<10}")
    log_output("-" * 55)

    for file_path in target_csvs:
        total_in_file = file_stats[file_path]
        percentage = (total_intersection / total_in_file) * 100 if total_in_file > 0 else 0

        log_output(f"{file_path:<30} {total_in_file:<15,} {percentage:<10.1f}%")

    conn.close()
    log_output("\n" + "=" * 80)

    def transform_path(path):
        parts = path.split('/')
        parts = parts[1:]
        filename = parts[-1].replace('.csv.zst', '')
        rest = parts[:-1]
        return '_'.join(rest + [filename])

    # Write results to file
    output_dir = os.path.join(EXP_INTERSECTIONS, "+".join([transform_path(p) for p in target_csvs]))
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "info.txt")

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))

        log_output(f"\n✅ Results saved to: {output_file}")

    except Exception as e:
        print(f"\n❌ Error writing to file {output_file}: {e}")


class ProcessingParams:
    def __init__(self, num_workers: int, batch_size: int, total_rows: int, total_samples: int, targets_csv: str,
                 is_os_scan: bool, probing_csv: str, eval_csv: str, result_dir: str, analysis_dir: str):
        self.num_workers = num_workers
        self.batch_size = batch_size
        self.total_rows = total_rows
        self.total_samples = total_samples
        self.targets_csv = targets_csv
        self.is_os_scan = is_os_scan
        self.probing_csv = probing_csv
        self.eval_csv = eval_csv
        self.result_dir = result_dir
        self.analysis_dir = analysis_dir
        self.pool = mp.Pool(processes=self.num_workers)

    def chunk_size(self) -> int:
        return self.batch_size * self.num_workers

    def samples_per_chunk(self) -> int:
        total_chunks = int(math.ceil(self.total_rows / self.chunk_size()))
        return int(round(self.total_samples / float(total_chunks)))

    def targets_ip_csv(self) -> str:
        if self.is_os_scan:
            real_targets_os_csv = os.readlink(self.targets_csv)
            real_targets_os_dir = os.path.dirname(real_targets_os_csv)
            return os.path.join(real_targets_os_dir, "targets.csv.zst")
        return self.targets_csv

    def targets_os_csv(self) -> str:
        if self.is_os_scan:
            return self.targets_csv
        raise ValueError("This result is not based on OS scan")

    def save(self):
        os.makedirs(self.analysis_dir, exist_ok=True)
        params = {
            "Number of Workers": self.num_workers,
            "Batch Size": self.batch_size,
            "Total Rows": self.total_rows,
            "Total Samples": self.total_samples,
            "Targets CSV": self.targets_csv,
            "Is OS Scan": self.is_os_scan,
            "Probing CSV": self.probing_csv,
            "Eval CSV": self.eval_csv,
            "Result Dir": self.result_dir,
            "Analysis Dir": self.analysis_dir
        }
        with open(os.path.join(self.analysis_dir, "params.txt"), "w") as f:
            for key, value in params.items():
                f.write(f"{key}: {value}\n")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("Cleanup...")
        self.pool.close()
        self.pool.join()

        for file in glob.glob(os.path.join(self.result_dir, "*.tmp")):
            os.remove(file)


def count_pattern(batch: pd.DataFrame) -> collections.Counter:
    return Counter(batch["IP_ID_PATTERN"])


def plot_pattern_distribution(params: ProcessingParams):
    print("Computing Pattern Distribution...")
    pattern_counter = Counter()
    dctx = zstd.ZstdDecompressor()

    with open(params.eval_csv, "rb") as f:
        with dctx.stream_reader(f) as reader:
            with io.TextIOWrapper(reader, encoding="utf-8") as text_reader:
                progress_bar = tqdm(total=params.total_rows, unit="rows")

                try:
                    for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size(),
                                                usecols=["IP", "IP_ID_PATTERN"]):
                        batches = [chunk_df[i:i + params.batch_size] for i in
                                   range(0, len(chunk_df), params.batch_size)]

                        for batch_pattern_counter in params.pool.map(count_pattern, batches):
                            pattern_counter.update(batch_pattern_counter)

                        progress_bar.update(len(chunk_df))
                finally:
                    progress_bar.close()

    total = sum(pattern_counter.values())
    df = pd.DataFrame(list(pattern_counter.items()), columns=['class', 'absolute'])
    df['relative'] = (df['absolute'] / float(total)) * 100

    full_order = [p.value for p in Pattern]
    order = [p for p in full_order if p in df["class"].values]

    # Plot
    print("Plotting Pattern Distribution...")
    plt.figure(figsize=(7, 7))
    ax = sns.barplot(
        x="class",
        y="relative",
        data=df[["class", "relative"]],
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

    output_dir = os.path.join(params.analysis_dir, "pattern_distribution")
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total Absolute: {total}\n")
        f.write(f"Class Distribution:\n{df.to_string(index=False)}")
    df.to_pickle(os.path.join(output_dir, "data.pkl"))
    plt.savefig(os.path.join(output_dir, "plot.pdf"), bbox_inches="tight")

    plt.close()


def merge_csv(csv_a: str, csv_b: str, on: str) -> str:
    output_dir = os.path.dirname(csv_a)
    csv_a_id = os.path.basename(csv_a).removesuffix(".csv.zst")
    csv_b_id = os.path.basename(csv_b).removesuffix(".csv.zst")
    output_path = os.path.join(output_dir, f"{csv_a_id}+{csv_b_id}.csv.zst.tmp")

    if os.path.exists(output_path):
        return output_path

    conn = duckdb.connect()

    query = f"""
        COPY (
            SELECT a.*, b.*
            FROM read_csv_auto('{csv_a}', compression='zstd') a
            JOIN read_csv_auto('{csv_b}', compression='zstd') b
            ON a.{on} = b.{on}
        ) TO '{output_path}' (COMPRESSION 'zstd', FORMAT CSV, HEADER);
        """

    conn.execute(query)
    conn.close()
    return output_path


def plot_pattern_distribution_for_oses(params: ProcessingParams, oses: list[str]):
    print(f"Computing Pattern Distribution for OSes {oses}...")
    merged_csv = merge_csv(params.eval_csv, params.targets_os_csv(), on="IP")

    pattern_counter = Counter()
    dctx = zstd.ZstdDecompressor()

    with open(merged_csv, "rb") as merge_f:
        with dctx.stream_reader(merge_f) as reader:
            with io.TextIOWrapper(reader, encoding="utf-8") as text_reader:
                progress_bar = tqdm(total=params.total_rows, unit="rows")

                try:
                    for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size(),
                                                usecols=["IP", "IP_ID_PATTERN", "OS"]):
                        chunk_length = len(chunk_df)
                        chunk_df = chunk_df[chunk_df["OS"].isin(oses)]

                        batches = [chunk_df[i:i + params.batch_size] for i in
                                   range(0, len(chunk_df), params.batch_size)]

                        for batch_pattern_counter in params.pool.map(count_pattern, batches):
                            pattern_counter.update(batch_pattern_counter)

                        progress_bar.update(chunk_length)
                finally:
                    progress_bar.close()

    total = sum(pattern_counter.values())
    df = pd.DataFrame(list(pattern_counter.items()), columns=['class', 'absolute'])
    df['relative'] = (df['absolute'] / float(total)) * 100

    full_order = [p.value for p in Pattern]
    order = [p for p in full_order if p in df["class"].values]

    # Plot
    print(f"Plotting Pattern Distribution for OSes {oses}...")
    plt.figure(figsize=(7, 7))
    ax = sns.barplot(
        x="class",
        y="relative",
        data=df[["class", "relative"]],
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

    output_dir = os.path.join(params.analysis_dir, "pattern_distribution_for_oses", "+".join(oses))
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total Absolute: {total}\n")
        f.write(f"Class Distribution:\n{df.to_string(index=False)}")
    df.to_pickle(os.path.join(output_dir, "data.pkl"))
    plt.savefig(os.path.join(output_dir, "plot.pdf"), bbox_inches="tight")

    plt.close()


def calc_time_between_requests(rows_batch: list[np.ndarray]) -> list[np.ndarray]:
    results = []

    for row_data in rows_batch:
        results.append(np.diff(row_data) / 1e3)

    return results


def plot_time_between_requests(params: ProcessingParams):
    print("Computing Time Between Requests...")
    time_between_requests = []
    dctx = zstd.ZstdDecompressor()

    def prepare_row_data(row) -> np.ndarray:
        return np.fromstring(row.SENT_TS_SEQUENCE, sep=",", dtype=np.int64)

    with open(params.probing_csv, "rb") as f:
        with dctx.stream_reader(f) as reader:
            with io.TextIOWrapper(reader, encoding="utf-8") as text_reader:
                progress_bar = tqdm(total=params.total_rows, unit="rows")

                try:
                    for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size(),
                                                usecols=["SENT_TS_SEQUENCE"]):
                        sample_df = chunk_df.sample(n=min(len(chunk_df), params.samples_per_chunk()))
                        all_rows = []

                        for row in sample_df.itertuples(index=False):
                            try:
                                row_data = prepare_row_data(row)
                                all_rows.append(row_data)
                            except Exception:
                                continue

                        batches = [all_rows[i:i + params.batch_size] for i in
                                   range(0, len(all_rows), params.batch_size)]

                        for deltas in params.pool.map(calc_time_between_requests, batches):
                            time_between_requests.extend(deltas)

                        progress_bar.update(len(chunk_df))
                finally:
                    progress_bar.close()

    # Plot
    print(f"Total datapoints: {len(time_between_requests)}")
    print("Plotting Time Between Requests...")
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

    output_dir = os.path.join(params.analysis_dir, "time_between_requests")
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total Hist Values: {len(deltas_cut)}\n")
    np.save(os.path.join(output_dir, "data.npy"), deltas_cut)
    plt.savefig(os.path.join(output_dir, "plot.pdf"), bbox_inches="tight")

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
    print("Computing Avg RTT Per Continent...")
    continent_to_rtts = {}
    dctx = zstd.ZstdDecompressor()
    total_rtt_count = 0

    with open(params.eval_csv, "rb") as f:
        with dctx.stream_reader(f) as reader:
            with io.TextIOWrapper(reader, encoding="utf-8") as text_reader:
                progress_bar = tqdm(total=params.total_rows, unit="rows")

                try:
                    for chunk_df in pd.read_csv(text_reader, chunksize=params.chunk_size(), usecols=["IP", "AVG_RTT"]):
                        sample_df = chunk_df.sample(n=min(len(chunk_df), params.samples_per_chunk()))
                        batches = [sample_df[i:i + params.batch_size] for i in
                                   range(0, len(sample_df), params.batch_size)]

                        for batch_continent_to_rtts in params.pool.map(get_continent_rtts, batches):
                            for continent, rtts in batch_continent_to_rtts.items():
                                total_rtt_count += len(rtts)
                                continent_to_rtts.setdefault(continent, []).extend(rtts)

                        progress_bar.update(len(chunk_df))
                finally:
                    progress_bar.close()

    # Plot
    continent_to_rtts_numpy = {}
    continents = {}
    for continent, rtts in continent_to_rtts.items():
        arr = np.array(rtts, dtype=np.float32)
        q = np.percentile(arr, 99)
        arr_cut = arr[arr <= q]

        rtt_count = len(arr_cut)
        if rtt_count < total_rtt_count * 0.01:
            continue

        continent_to_rtts_numpy[continent] = arr_cut
        continents[continent] = rtt_count

    order = sorted(continents, key=continents.get, reverse=True)

    print(f"Total datapoints: {sum(continents.values())} - {continents}")
    print("Plotting Avg RTT Per Continent...")

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

    output_dir = os.path.join(params.analysis_dir, "rtt_per_continent")
    os.makedirs(output_dir, exist_ok=True)
    df_counts = df.groupby("continent").size().reset_index(name="rtts_count")
    with open(os.path.join(output_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total Count: {df_counts["rtts_count"].sum()}\n")
        f.write(f"RTTs Count Per Continent:\n{df_counts.to_string(index=False)}")
    df.to_pickle(os.path.join(output_dir, "data.pkl"))
    plt.savefig(os.path.join(output_dir, "plot.pdf"), bbox_inches="tight")

    plt.close()


def get_increments_for_pattern(rows_batch: list[np.ndarray], pattern: Pattern) -> list[np.ndarray]:
    results = []

    for row_data in rows_batch:
        ip_id_sequence = IPIDSequence(row_data)
        if pattern in {Pattern.LOCAL_EQ1, Pattern.LOCAL_GE1}:
            results.append(np.concatenate([ip_id_sequence.even.increments, ip_id_sequence.odd.increments]))
        elif pattern == Pattern.MULTI_GLOBAL:
            clusters = get_clusters(ip_id_sequence.full.sequence)
            increments = np.array([], dtype=np.int32)
            for cluster in clusters:
                increments = np.concatenate([increments, np.diff(cluster)])
            results.append(increments)
        else:
            # if np.any(ip_id_sequence.full.increments < 700):
            #     print(
            #         f"seq={ip_id_sequence.full.sequence} incs={ip_id_sequence.full.increments} ==> p_value={p_value(ip_id_sequence.full.increments)} > 0.01 ==> is_random is True")
            results.append(ip_id_sequence.full.increments)

    return results


def plot_increment_distribution(params: ProcessingParams, pattern: Pattern):
    print(f"Computing Increment Distribution for {pattern.value}...")
    increments = []
    probing_dctx = zstd.ZstdDecompressor()
    eval_dctx = zstd.ZstdDecompressor()
    worker_func = partial(get_increments_for_pattern, pattern=pattern)

    def prepare_row_data(row) -> np.ndarray:
        return np.fromstring(row.IP_ID_SEQUENCE, sep=",", dtype=np.int32)

    with open(params.probing_csv, "rb") as probing_f, open(params.eval_csv, "rb") as eval_f:
        with probing_dctx.stream_reader(probing_f) as probing_reader, \
                eval_dctx.stream_reader(eval_f) as eval_reader:
            with io.TextIOWrapper(probing_reader, encoding="utf-8") as probing_text_reader, \
                    io.TextIOWrapper(eval_reader, encoding="utf-8") as eval_text_reader:
                progress_bar = tqdm(total=params.total_rows, unit="rows")

                try:
                    probing_iter = pd.read_csv(probing_text_reader, chunksize=params.chunk_size(),
                                               usecols=["IP", "IP_ID_SEQUENCE"])
                    eval_iter = pd.read_csv(eval_text_reader, chunksize=params.chunk_size(),
                                            usecols=["IP", "IP_ID_PATTERN"])

                    for probing_chunk_df in probing_iter:
                        eval_chunk_df = next(eval_iter)

                        assert probing_chunk_df["IP"].equals(eval_chunk_df["IP"])
                        chunk_df = pd.concat([probing_chunk_df, eval_chunk_df.drop(columns="IP")], axis=1)
                        chunk_length = len(chunk_df)

                        chunk_df = chunk_df[chunk_df["IP_ID_PATTERN"] == pattern.value]
                        sample_df = chunk_df.sample(n=min(len(chunk_df), params.samples_per_chunk()))

                        all_rows = []
                        for row in sample_df.itertuples(index=False):
                            try:
                                assert row.IP_ID_PATTERN == pattern.value
                                row_data = prepare_row_data(row)
                                all_rows.append(row_data)
                            except Exception:
                                continue

                        batches = [all_rows[i:i + params.batch_size] for i in
                                   range(0, len(all_rows), params.batch_size)]

                        for batch_increments_for_pattern in params.pool.map(worker_func, batches):
                            increments.extend(batch_increments_for_pattern)

                        progress_bar.update(chunk_length)
                finally:
                    progress_bar.close()

    # Plot
    print(f"Total datapoints: {len(increments)}")
    print(f"Plotting Increment Distribution for {pattern.value}...")
    increments_numpy = np.array(increments, dtype=np.int32)
    q = np.percentile(increments_numpy, 99)
    increments_cut = increments_numpy[increments_numpy <= q]

    plt.figure(figsize=(10, 6))
    sns.histplot(increments_cut, bins=100, stat="percent")
    plt.xlabel("IP-ID Increment", fontsize=18)
    plt.xticks(fontsize=16)
    plt.xlim(left=0)
    plt.ylabel("Relative Frequency (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="both", linestyle="--", alpha=0.6)
    plt.tight_layout()

    output_dir = os.path.join(params.analysis_dir, "inc_distribution", pattern.value.lower().replace(" ", ""))
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total Hist Values: {len(increments_cut)}\n")
    np.save(os.path.join(output_dir, "data.npy"), increments_cut)
    plt.savefig(os.path.join(output_dir, "plot.pdf"), bbox_inches="tight")

    plt.close()


def start(result_dir: str):
    start_time = time.time()

    eval_csv = os.path.join(result_dir, "eval.csv.zst")
    probing_csv = os.path.join(result_dir, "probing.csv.zst")
    targets_ip_csv = os.path.join(result_dir, "targets.csv.zst")
    targets_os_csv = os.path.join(result_dir, "targets_os.csv.zst")

    if os.path.exists(targets_os_csv):
        targets_csv = targets_os_csv
        is_os_scan = True
    else:
        targets_csv = targets_ip_csv
        is_os_scan = False

    plot_output_dir = os.path.join(result_dir, "analysis")
    os.makedirs(plot_output_dir, exist_ok=True)

    num_workers = max(1, mp.cpu_count() - 1)
    print(f"Using {num_workers} workers for processing")

    batch_size = 5000
    total_samples = 300_000

    print(f"Counting lines of probing_csv file...")
    total_rows_probing_csv = count_lines_in_zst(probing_csv)
    print(f"Total {total_rows_probing_csv} rows to process for probing_csv")

    print(f"Counting lines of eval_csv file...")
    total_rows_eval_csv = count_lines_in_zst(eval_csv)
    print(f"Total {total_rows_eval_csv} rows to process for eval_csv")

    assert total_rows_eval_csv == total_rows_probing_csv, "probing_csv and eval_csv should have same line count!"

    with ProcessingParams(num_workers=num_workers, batch_size=batch_size, total_rows=total_rows_probing_csv,
                          total_samples=total_samples, targets_csv=targets_csv, is_os_scan=is_os_scan,
                          probing_csv=probing_csv, eval_csv=eval_csv, result_dir=result_dir,
                          analysis_dir=plot_output_dir) as params:
        # params.save()
        # plot_pattern_distribution(params)
        # plot_time_between_requests(params)
        # plot_avg_rtt_per_continent(params)
        # plot_increment_distribution(params, Pattern.GLOBAL)
        # plot_increment_distribution(params, Pattern.LOCAL_GE1)
        plot_increment_distribution(params, Pattern.RANDOM)
        # plot_increment_distribution(params, Pattern.MULTI_GLOBAL)
        # plot_increment_distribution(params, Pattern.REFLECTION)

        # if params.is_os_scan:
        #     plot_pattern_distribution_for_oses(params, linux_distros)
        #     plot_pattern_distribution_for_oses(params, windows)
        #     plot_pattern_distribution_for_oses(params, bsd)
        #     plot_pattern_distribution_for_oses(params, apple)

        print(f"Analysis finished: {runtime(start_time)} result=[{plot_output_dir}]")
