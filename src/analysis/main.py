import os.path
import time

import geoip2.database
import matplotlib.pyplot as plt
import numpy as np
import polars as pl
import seaborn as sns

from core.classifier import Pattern, IPIDSequence
from core.utils import config, runtime
from postproc import GEOLITE_COUNTRY_DB
from postproc.main import get_continent, parse_tuple_column


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


def plot_pattern_distribution(eval_csv: str, output_dir: str):
    eval_lf = pl.scan_csv(eval_csv).select("IP_ID_PATTERN").collect()
    data = eval_lf["IP_ID_PATTERN"].value_counts().sort("count", descending=True).to_pandas()
    data["percent"] = (data["count"] / data["count"].sum()) * 100

    full_order = [p.value for p in Pattern]
    order = [p for p in full_order if p in set(data["IP_ID_PATTERN"])]

    plt.figure(figsize=(7, 7))
    ax = sns.barplot(
        x="IP_ID_PATTERN",
        y="percent",
        data=data,
        order=order
    )
    for i, row in data.iterrows():
        _i = order.index(row["IP_ID_PATTERN"])
        ax.text(_i, row["percent"] + 1, f"{row['percent']:.1f}%", ha='center', fontsize=16)
    plt.xlabel("Class", fontsize=18)
    plt.xticks(rotation=60, fontsize=16)
    plt.ylabel("Percentage (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0, top=100)
    plt.grid(True, axis="y", linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "pattern_distribution.pdf"), bbox_inches="tight")
    plt.close()


def plot_time_between_requests(probing_csv: str, output_dir: str):
    df = (
        pl.scan_csv(probing_csv)
        .select(pl.col("SENT_TS_SEQUENCE")
                .str.split(",")
                .list.eval(pl.element().cast(pl.Int64))
                .alias("ts_list"))
        .collect()
    )

    deltas = (
        df.select(pl.col("ts_list").list.eval(
            pl.element().diff().drop_nulls()))
        .explode("ts_list")
        .with_columns((pl.col("ts_list") / 1e3).alias("delta_ms"))
        .select("delta_ms")
    )

    filtered = deltas.filter(pl.col("delta_ms") <= deltas["delta_ms"].quantile(0.999))
    hist_data = filtered.to_series().to_numpy()

    plt.figure(figsize=(10, 6))
    sns.histplot(hist_data, bins=100, stat="percent")
    plt.xlabel("Time between Requests (ms)", fontsize=18)
    plt.xticks(fontsize=16)
    plt.xlim(left=0)
    plt.ylabel("Relative Frequency (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="both", linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "time_between_requests.pdf"), bbox_inches="tight")
    plt.close()


def plot_avg_rtt_per_continent(eval_csv: str, output_dir: str):
    country_reader = geoip2.database.Reader(GEOLITE_COUNTRY_DB)

    lf = (
        pl.scan_csv(eval_csv)
        .select(["IP", "AVG_RTT"])
        .with_columns([
            (pl.col("AVG_RTT") / 1e3).alias("rtts"),  # Microseconds to milliseconds
            pl.col("IP").map_elements(lambda ip: get_continent(country_reader, ip), return_dtype=pl.Utf8).alias(
                "continent")
        ])
        .select(["rtts", "continent"])
    )

    df = lf.collect()
    country_reader.close()

    high = df["rtts"].quantile(0.99)
    df = df.filter(pl.col("rtts") <= high)

    continent_counts = df.group_by("continent").count()
    total = continent_counts["count"].sum()
    valid_continents = continent_counts.filter(pl.col("count") / total >= 0.01)["continent"]
    df = df.filter(pl.col("continent").is_in(valid_continents))

    order = (continent_counts
             .filter(pl.col("continent").is_in(valid_continents))
             .sort("count", descending=True)["continent"]
             .to_list())

    plt.figure(figsize=(10, 6))
    sns.violinplot(data=df.to_pandas(), x="continent", y="rtts", density_norm="count", inner="quartile", order=order)
    plt.xlabel("")
    plt.xticks(rotation=30, fontsize=16)
    plt.ylabel("Average RTT (ms)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="y", linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "rtt_per_continent.pdf"), bbox_inches="tight")
    plt.close()


def plot_increment_distribution(probing_csv: str, eval_csv: str, pattern: Pattern, output_dir: str):
    ip_lf = (
        pl.scan_csv(eval_csv)
        .select(["IP", "IP_ID_PATTERN"])
        .filter(pl.col("IP_ID_PATTERN") == pattern.value)
        .select("IP")
    )

    df = (
        pl.scan_csv(probing_csv)
        .select(["IP", "IP_ID_SEQUENCE"])
        .join(ip_lf, on="IP", how="inner")
        .with_columns([
            parse_tuple_column(pl.col("IP_ID_SEQUENCE")).alias("ip_ids")
        ])
        .select("ip_ids")
        .collect()
    )

    def get_increments_of_ip_ids(ip_ids: list[int]) -> np.ndarray:
        ip_id_sequence = IPIDSequence(ip_ids)
        if pattern in {Pattern.LOCAL_EQ1, Pattern.LOCAL_GE1}:
            return np.concatenate([ip_id_sequence.even.increments, ip_id_sequence.odd.increments])
        return ip_id_sequence.full.increments

    increments = (
        df.with_columns(
            pl.col("ip_ids").map_elements(get_increments_of_ip_ids, return_dtype=pl.List(pl.Int64))
            .alias("increments")
        )
        .explode("increments")
        .select("increments")
    )

    filtered = increments.filter(pl.col("increments") <= increments["increments"].quantile(0.99))
    hist_data = filtered.to_series().to_numpy()

    plt.figure(figsize=(10, 6))
    sns.histplot(hist_data, bins=100, stat="percent")
    plt.xlabel("IP-ID Increment", fontsize=18)
    plt.xticks(fontsize=16)
    plt.xlim(left=0)
    plt.ylabel("Relative Frequency (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0)
    plt.grid(True, axis="both", linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"inc_distribution_{pattern.value.lower().replace(" ", "")}.pdf"),
                bbox_inches="tight")
    plt.close()


def start(result_dir: str):
    start_time = time.time()

    eval_csv = os.path.join(result_dir, "eval.csv.zst")
    probing_csv = os.path.join(result_dir, "probing.csv.zst")

    plot_output_dir = os.path.join(result_dir, "analysis")
    os.makedirs(plot_output_dir, exist_ok=True)

    plot_pattern_distribution(eval_csv, plot_output_dir)
    plot_time_between_requests(probing_csv, plot_output_dir)
    plot_avg_rtt_per_continent(eval_csv, plot_output_dir)
    plot_increment_distribution(probing_csv, eval_csv, Pattern.GLOBAL, plot_output_dir)
    plot_increment_distribution(probing_csv, eval_csv, Pattern.LOCAL_GE1, plot_output_dir)
    plot_increment_distribution(probing_csv, eval_csv, Pattern.RANDOM, plot_output_dir)

    print(f"Analysis finished: {runtime(start_time)} result=[{plot_output_dir}]")
