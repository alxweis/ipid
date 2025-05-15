import os.path

import matplotlib.pyplot as plt
import numpy as np
import polars as pl
import seaborn as sns

from core.classifier import Pattern
from core.utils import config


def analyze_response_rate(targets_file: str, ts_name: str):
    lf = pl.scan_csv(targets_file)

    min_ts = lf.select(pl.min(ts_name)).collect().item()

    histogram_data = lf.select(
        ((pl.col(ts_name) - min_ts) / 3600).alias("hours_since_start")
    ).collect()

    plt.figure(figsize=(12, 6))
    plt.hist(
        histogram_data["hours_since_start"],
        bins=50,
        edgecolor='black',
        linewidth=1.0,
        alpha=0.75
    )
    plt.xlabel('Time (h)', fontsize=12)
    plt.ylabel(f'Number of {"Collected IP Addresses" if ts_name == config.ts_ip_col_name else "Detected OSes"}',
               fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()

    image_file = os.path.join(os.path.dirname(targets_file),
                              f'{"ip" if ts_name == config.ts_ip_col_name else "os"}_response_rate.png')
    plt.savefig(image_file)
    print(f"Plot has been saved as: {image_file}")


# TODO Plot Violin plot of average RTT per continent
# TODO Plot Histogram of IP-ID increments for IP-ID sequences classified as Global
# TODO Plot Histogram of IP-ID increments for IP-ID sequences classified as Local (=1) and Local (>=1)

def plot_pattern_distribution(eval_csv: str, result_dir: str):
    eval_lf = pl.scan_csv(eval_csv).select("IP_ID_PATTERN").collect()
    data = eval_lf["IP_ID_PATTERN"].value_counts().sort("count", descending=True).to_pandas()
    data["percent"] = (data["count"] / data["count"].sum()) * 100

    plt.figure(figsize=(7, 7))
    full_order = [p.value for p in Pattern]
    order = [p for p in full_order if p in set(data["IP_ID_PATTERN"])]
    ax = sns.barplot(
        x="IP_ID_PATTERN",
        y="percent",
        data=data,
        order=order
    )
    plt.xticks(rotation=60, fontsize=16)
    plt.yticks(fontsize=16)
    plt.xlabel("Class", fontsize=18)
    plt.ylabel("Percentage (%)", fontsize=18)
    for i, row in data.iterrows():
        _i = order.index(row["IP_ID_PATTERN"])
        ax.text(_i, row["percent"] + 1, f"{row['percent']:.1f}%", ha='center', fontsize=16)
    plt.ylim(0, 100)
    plt.tight_layout()
    plt.savefig(os.path.join(result_dir, "pattern_distribution.png"))
    plt.close()


def plot_time_between_requests(probing_csv: str, result_dir: str):
    send_ts = (
        pl.scan_csv(probing_csv)
        .select(pl.col("SEND_TS_SEQUENCE").str.strip_chars("()").str.split(",").list.eval(pl.element().cast(pl.Int64)).alias("send_ts"))
        .collect()
        .select("send_ts")
    )

    diffs = []
    for row in send_ts.iter_rows():
        ts = row[0]
        if ts and len(ts) > 1:
            d = np.diff(ts) / 1e3 # Microseconds to milliseconds
            diffs.append(d)

    diffs = np.concatenate(diffs)
    lower = np.percentile(diffs, 0.1)
    upper = np.percentile(diffs, 99.9)
    filtered = diffs[(diffs >= lower) & (diffs <= upper)]

    plt.figure(figsize=(10, 7))
    sns.histplot(filtered, bins=80, stat="percent")
    plt.xticks(fontsize=16)
    plt.yticks(fontsize=16)
    plt.xlabel("Time between Requests (ms)", fontsize=18)
    plt.ylabel("Relative Frequency (%)", fontsize=18)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(result_dir, "time_between_requests.png"))
    plt.close()


def start(result_dir: str):
    eval_csv = os.path.join(result_dir, "eval.csv")
    probing_csv = os.path.join(result_dir, "probing.csv")
    # asn_csv = os.path.join(ASN_CSV)

    plot_pattern_distribution(eval_csv, result_dir)
    plot_time_between_requests(probing_csv, result_dir)
