import bz2
import csv
import io
import ipaddress
import os
import sys
from datetime import datetime

import matplotlib.pyplot as plt
import zstandard as zstd

from analysis.main import plot_response_rate, calc_intersections
from core.utils import config
from experimental.sequence_stable_len_analysis.main import (
    analyze_sequence_stable_lens_synthetic,
    analyze_sequence_stable_lens_natural
)

filename = os.path.basename(__file__)


def print_usage():
    print("Usage:")
    print(f"  python {filename} <mode> [additional arguments]")
    print("\nModes:")
    print("  1 - Analyze Synthetic Sequence Lengths for Stable Classification:")
    print(f"    python {filename} 1 <sequence_count_per_pattern> <sequence_length>")
    print("  2 - Analyze Natural Sequence Lengths for Stable Classification:")
    print(f"    python {filename} 2 <result_path>")
    print("  3 - Analyze Response Rate for IP-Scan or OS-Scan:")
    print(f"    python {filename} 3 <targets_full_path>")
    print("  4 - Analyze Intersections:")
    print(f"    python {filename} 4 <targets_full_path> <targets_full_path> ...")
    print("  5 - Create routers.csv.zst:")
    print(f"    python {filename} 5 <router_nodes_path>")
    print("  6 - Quick Plot IP-ID Sequence:")
    print(f"    python {filename} 6 <ip_id_sequence>")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    try:
        mode = int(sys.argv[1])
    except ValueError:
        print("Mode must be an integer.")
        print_usage()
        return

    if mode == 1:
        if len(sys.argv) != 4:
            print_usage()
            return
        count = int(sys.argv[2])
        length = int(sys.argv[3])

        analyze_sequence_stable_lens_synthetic(sequence_count_per_pattern=count, sequence_length=length)
    elif mode == 2:
        if len(sys.argv) != 3:
            print_usage()
            return
        result_path = sys.argv[2]

        probing_csv = os.path.join(result_path, "probing.csv.zst")
        analyze_sequence_stable_lens_natural(probing_csv=probing_csv)
    elif mode == 3:
        if len(sys.argv) != 3:
            print_usage()
            return
        targets_full_path = sys.argv[2]

        file_name = os.path.basename(targets_full_path)
        if file_name == "targets.csv.zst":
            ts_type = "ip"
        elif file_name == "targets_os.csv.zst":
            ts_type = "os"
        else:
            raise ValueError(f"{targets_full_path} is an invalid targets full path!")
        plot_response_rate(targets_csv=targets_full_path, ts_type=ts_type)
    elif mode == 4:
        if len(sys.argv) < 3:
            print_usage()
            return

        targets_full_paths = sys.argv[2:]
        calc_intersections(targets_full_paths, on="IP")
    elif mode == 5:
        if len(sys.argv) < 3:
            print_usage()
            return

        router_nodes_path = sys.argv[2]
        output_path = os.path.join(os.path.dirname(router_nodes_path), "routers.csv.zst")

        with bz2.open(router_nodes_path, 'rt') as infile, open(output_path, 'wb') as out_f:
            zstd_writer = zstd.ZstdCompressor().stream_writer(out_f)
            text_writer = io.TextIOWrapper(zstd_writer, encoding='utf-8', newline='')
            csv_writer = csv.writer(text_writer)

            csv_writer.writerow([config.ip_col_name])

            for line in infile:
                if line.startswith('node'):
                    parts = line.strip().split()
                    # node_id = parts[1][:-1]
                    ips = parts[2:]
                    first_valid_ip = next(
                        (ip for ip in ips if ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network('224.0.0.0/3')),
                        None
                    )
                    if first_valid_ip:
                        csv_writer.writerow([str(first_valid_ip)])

            zstd_writer.flush()
            text_writer.detach()
            zstd_writer.close()
    elif mode == 6:
        if len(sys.argv) < 3:
            print_usage()
            return

        l = sys.argv[2].strip("[]")
        y_values = list(map(int, l.split()))
        x_values = list(range(1, len(y_values) + 1))
        plt.plot(x_values, y_values, marker='o')
        plt.xlabel("Index")
        plt.ylabel("Value")
        plt.title("Plot of values")
        plt.grid(True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = f"plot_{timestamp}.png"
        plt.savefig(fn)
        print(f"Plot saved as {fn}")
    else:
        print_usage()


if __name__ == "__main__":
    main()
