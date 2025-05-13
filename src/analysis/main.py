import os.path

import matplotlib.pyplot as plt
import polars as pl

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


def start(result_dir: str):
    pass
