import bz2
import csv
import io
import ipaddress
import os
import shutil
import sys
from datetime import datetime

import duckdb
import matplotlib.pyplot as plt
import zstandard as zstd

from analysis.main import plot_response_rate, calc_intersections, intersect_classifications, filter_ips_by_class
from core.classifier import pattern_generation_map, chi2_test, autocorr, dir_switch_count, AUTOCORR_MAX_LAG
from core.utils import config
from experimental.sequence_stable_len_analysis.main import (
    analyze_sequence_stable_lens_synthetic,
    analyze_sequence_stable_lens_natural
)
from hitlist.ip_scan import post_cleanup

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
    print("  7 - Classification Intersection:")
    print(f"    python {filename} 7 <eval_file_path_seq> <eval_file_path_b2b>")
    print("  8 - Cleanup Targets CSV:")
    print(f"    python {filename} 8 <targets_full_path>")
    print("  9 - Create hitlist from evaluation with class filter:")
    print(f"    python {filename} 9 <eval_path> <class_filter>")
    print("  10 - Compute value ranges for random class metrics:")
    print(f"    python {filename} 10 <sequence_length>")
    print("  11 - Merge SEQ and MASS measurement into SEQ and delete MASS:")
    print(f"    python {filename} 11 <seq_msm_path> <mass_msm_path>")
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

        y_values = list(map(int, sys.argv[2].split(",")))
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
    elif mode == 7:
        if len(sys.argv) < 4:
            print_usage()
            return

        eval_csv_seq_path = sys.argv[2]
        eval_csv_b2b_path = sys.argv[3]

        intersect_classifications(eval_csv_seq_path, eval_csv_b2b_path)
    elif mode == 8:
        if len(sys.argv) < 3:
            print_usage()
            return

        targets_full_path = sys.argv[2]
        post_cleanup(targets_full_path)
    elif mode == 9:
        if len(sys.argv) < 4:
            print_usage()
            return

        eval_csv_path = sys.argv[2]
        class_filter = sys.argv[3]
        output_file = filter_ips_by_class(eval_csv_path, class_filter.split(","))
        print(f"Result saved in {output_file}")
    elif mode == 10:
        if len(sys.argv) < 3:
            print_usage()
            return

        sequence_length = int(sys.argv[2])
        sequence_count_per_pattern = 10000

        chi2_result: dict[str, tuple[float, float]] = {}
        dir_switch_result: dict[str, tuple[int, int]] = {}
        autocorr_result: dict[str, tuple[float, float]] = {}

        def update_range(d: dict, key: str, value_min: float, value_max: float) -> None:
            if key in d:
                old_min, old_max = d[key]
                d[key] = min(old_min, value_min), max(old_max, value_max)
            else:
                d[key] = value_min, value_max

        for pattern, generator in pattern_generation_map.items():
            if generator is None:
                continue

            for _ in range(sequence_count_per_pattern):
                seq = generator(sequence_length)

                p_chi2 = chi2_test(seq)
                turns = dir_switch_count(seq)
                autocorrs = [autocorr(seq, lag) for lag in range(1, AUTOCORR_MAX_LAG + 1)]

                update_range(chi2_result, pattern.value, p_chi2, p_chi2)
                update_range(dir_switch_result, pattern.value, turns, turns)
                update_range(autocorr_result, pattern.value, min(autocorrs), max(autocorrs))

        def print_results(title: str, results: dict[str, tuple[float, float]]):
            print(f"{title}:")
            for pattern, (_min, _max) in results.items():
                print(f"{pattern}: {_min}...{_max}")
            print()

        print_results("Chi2 Result", chi2_result)
        print_results("Dir-Switch Result", dir_switch_result)
        print_results("Autocorr Result", autocorr_result)
    elif mode == 11:
        if len(sys.argv) < 4:
            print_usage()
            return

        seq_msm_path = str(sys.argv[2])
        mass_msm_path = str(sys.argv[3])
        merge_msm_path = seq_msm_path.replace("seq", "merge")

        merge_paths(seq_msm_path, mass_msm_path, merge_msm_path)
    else:
        print_usage()


def merge_paths(path_a: str, path_b: str, out_path: str, threads: int = os.cpu_count()):
    os.makedirs(out_path, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"PRAGMA threads={threads};")

    # Targets laden
    con.execute(f"""
        CREATE TABLE targets AS
        SELECT IP FROM read_csv_auto('{path_b}/targets.csv.zst', compression='zstd');
    """)

    def merge_file(fname: str):
        # Schema von A bestimmen
        cols = [c[0] for c in con.execute(
            f"DESCRIBE SELECT * FROM read_csv_auto('{path_a}/{fname}', compression='zstd')"
        ).fetchall()]
        cols.remove("IP")  # IP wird zum Join benutzt, nicht coalesced

        # Spaltenliste für COALESCE bauen
        select_cols = ["IP"]
        for col in cols:
            select_cols.append(f"COALESCE(b.{col}, a.{col}) AS {col}")
        select_sql = ", ".join(select_cols)

        query = f"""
            COPY (
              SELECT {select_sql}
              FROM (
                SELECT row_number() OVER () AS rn, *
                FROM read_csv_auto('{path_a}/{fname}', compression='zstd')
              ) a
              LEFT JOIN (
                SELECT * 
                FROM read_csv_auto('{path_b}/{fname}', compression='zstd')
                SEMI JOIN targets USING(IP)
              ) b
              USING(IP)
              ORDER BY rn
            )
            TO '{out_path}/{fname}' (FORMAT CSV, COMPRESSION ZSTD);
        """
        con.execute(query)

    # probing und eval mergen
    merge_file("probing.csv.zst")
    merge_file("eval.csv.zst")

    con.close()

    # targets.csv.zst von A als Symlink übernehmen (oder kopieren falls Datei)
    src = os.path.join(path_a, "targets.csv.zst")
    dst = os.path.join(out_path, "targets.csv.zst")
    if os.path.lexists(dst):
        os.remove(dst)
    if os.path.islink(src):
        target = os.readlink(src)
        os.symlink(target, dst)
    else:
        shutil.copy(src, dst)

    print(f"Merged {path_a} & {path_b} => {out_path}")
    print(f"Rerun analysis of {out_path} to get merged results!")


if __name__ == "__main__":
    main()
