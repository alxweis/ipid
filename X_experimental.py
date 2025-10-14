import bz2
import csv
import ipaddress
import json
import os
import pickle
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import duckdb
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import zstandard as zstd

from analysis.main import plot_response_rate, calc_intersections, intersect_classifications, filter_ips_by_class
from core import EXPERIMENTAL_RESULTS
from core.classifier import pattern_generation_map, chi2_test, autocorr, dir_switch_count, AUTOCORR_MAX_LAG, Pattern
from experimental.sequence_stable_len_analysis.main import (
    analyze_sequence_stable_lens_synthetic,
    analyze_sequence_stable_lens_natural
)
from hitlist.ip_scan import post_cleanup
from hitlist.os_scan import router, end_device, oses

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
    print("  5 - Process CAIDA ITDK dataset:")
    print(f"    python {filename} 5 <caida_itdk_path>")
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
    print("  12 - Crosscheck all interfaces per node should have same IP-ID pattern:")
    print(f"    python {filename} 12 <caida_itdk_path> <msm_path>")
    print("  13 - Analyze transit-hop IP-ID behavior:")
    print(f"    python {filename} 13 <caida_itdk_path> <msm_path>")
    print("  14 - Analyze end-device IP-ID behavior:")
    print(f"    python {filename} 14 <caida_itdk_path> <msm_path>")
    print("  15 - Plot transit-hop/end-host distribution:")
    print(f"    python {filename} 15 <msm_path> <protocol_name>")
    print("  16 - Plot pattern distribution by OS:")
    print(f"    python {filename} 16 <msm_path>")
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

        caida_itdk_path = sys.argv[2]
        ifaces_file = os.path.join(caida_itdk_path, "midar-iff.ifaces.bz2")
        nodes_file = os.path.join(caida_itdk_path, "midar-iff.nodes.bz2")

        # output files
        ip_to_node_file = os.path.join(caida_itdk_path, "ip_to_node.csv.zst")
        node_to_ips_file = os.path.join(caida_itdk_path, "node_to_ips.csv.zst")

        placeholder_net = ipaddress.ip_network("224.0.0.0/3")

        def is_placeholder(ip: str) -> bool:
            try:
                return ipaddress.ip_address(ip) in placeholder_net
            except ValueError:
                return True

        # -------------------------------------------------------------------
        # stream parse .ifaces -> temporary csv
        # -------------------------------------------------------------------
        def parse_ifaces_to_csv(tmpfile):
            with bz2.open(ifaces_file, "rt") as f, open(tmpfile, "w", newline="") as out:
                writer = csv.writer(out)
                writer.writerow(["IP", "NODE", "T", "D"])
                for line in f:
                    parts = line.strip().split()
                    if not parts:
                        continue
                    ip = parts[0]
                    if is_placeholder(ip):
                        continue
                    node, T, D = None, "0", "0"
                    for p in parts[1:]:
                        if p.startswith("N"):
                            node = p
                        elif p == "T":
                            T = "1"
                        elif p == "D":
                            D = "1"
                    if node:
                        writer.writerow([ip, node, T, D])

        # -------------------------------------------------------------------
        # stream parse .nodes -> temporary csv
        # -------------------------------------------------------------------
        def parse_nodes_to_csv(tmpfile):
            with bz2.open(nodes_file, "rt") as f, open(tmpfile, "w", newline="") as out:
                writer = csv.writer(out)
                writer.writerow(["NODE", "IP_LIST"])
                for line in f:
                    if not line.startswith("node"):
                        continue
                    parts = line.strip().split()
                    node = parts[1][:-1]
                    ips = [ip for ip in parts[2:] if not is_placeholder(ip)]
                    if ips:
                        writer.writerow([node, " ".join(ips)])

        # -------------------------------------------------------------------
        # compress csv -> .csv.zst
        # -------------------------------------------------------------------
        def compress_to_zst(input_csv, output_zst):
            with open(input_csv, "rb") as fin, open(output_zst, "wb") as fout:
                cctx = zstd.ZstdCompressor(level=10)
                with cctx.stream_writer(fout) as compressor:
                    for chunk in iter(lambda: fin.read(16384), b""):
                        compressor.write(chunk)

        con = duckdb.connect()

        tmp_ifaces = tempfile.mktemp(suffix=".csv")
        tmp_nodes = tempfile.mktemp(suffix=".csv")

        print("parsing .ifaces -> temp csv...")
        parse_ifaces_to_csv(tmp_ifaces)

        print("parsing .nodes -> temp csv...")
        parse_nodes_to_csv(tmp_nodes)

        con.execute(f"create table ip_to_node as select * from read_csv_auto('{tmp_ifaces}')")
        con.execute(f"create table node_to_ips as select * from read_csv_auto('{tmp_nodes}')")

        print("compressing ip_to_node.csv.zst ...")
        compress_to_zst(tmp_ifaces, ip_to_node_file)

        print("compressing node_to_ips.csv.zst ...")
        compress_to_zst(tmp_nodes, node_to_ips_file)

        os.remove(tmp_ifaces)
        os.remove(tmp_nodes)

        print("done!")
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

        assert seq_msm_path != mass_msm_path
        assert seq_msm_path != merge_msm_path
        assert mass_msm_path != merge_msm_path

        merge_paths(seq_msm_path, mass_msm_path, merge_msm_path)
    elif mode == 12:
        if len(sys.argv) < 4:
            print_usage()
            return

        node_to_ips_file = os.path.join(str(sys.argv[2]), "node_to_ips.csv.zst")
        eval_file = os.path.join(str(sys.argv[3]), "eval.csv.zst")

        con = duckdb.connect()

        # --- Load data ---
        con.execute(f"""
            create table eval as
            select * from read_csv_auto('{eval_file}', compression='zstd')
        """)

        con.execute(f"""
            create table node_to_ips as
            select * from read_csv_auto('{node_to_ips_file}', compression='zstd')
        """)

        # --- Explode IP_LIST into rows ---
        con.execute("""
            create table node_ip_map as
            select
                NODE,
                unnest(string_split(IP_LIST, ' ')) as IP
            from node_to_ips
        """)

        # --- Consistency analysis (only multi-IP nodes) ---
        result = con.execute("""
            with exploded as (
                select NODE, unnest(string_split(IP_LIST, ' ')) as IP
                from node_to_ips
            ),
            filtered as (
                select NODE, count(*) as ip_count
                from exploded
                group by NODE
                having count(*) > 1
            ),
            node_eval as (
                select e.NODE, v.IP_ID_PATTERN
                from exploded e
                join eval v on e.IP = v.IP
                where e.NODE in (select NODE from filtered)
            ),
            counts as (
                select NODE, count(distinct IP_ID_PATTERN) as pattern_count
                from node_eval
                group by NODE
            )
            select
                sum(case when pattern_count = 1 then 1 else 0 end) as consistent_nodes,
                count(*) as total_nodes,
                sum(case when pattern_count = 1 then 1 else 0 end)::double / count(*) as consistency_ratio
            from counts
        """).fetchdf()

        consistent_nodes = result["consistent_nodes"][0]
        total_nodes = result["total_nodes"][0]
        ratio = result["consistency_ratio"][0]

        print(f"Consistency ratio (only multi-IP nodes): {consistent_nodes} / {total_nodes} = {ratio:.6f}")

        # --- Pattern distribution for inconsistent nodes ---
        inconsistent_patterns = con.execute("""
            with exploded as (
                select NODE, unnest(string_split(IP_LIST, ' ')) as IP
                from node_to_ips
            ),
            filtered as (
                select NODE, count(*) as ip_count
                from exploded
                group by NODE
                having count(*) > 1
            ),
            node_eval as (
                select e.NODE, v.IP_ID_PATTERN
                from exploded e
                join eval v on e.IP = v.IP
                where e.NODE in (select NODE from filtered)
            ),
            counts as (
                select NODE, count(distinct IP_ID_PATTERN) as pattern_count
                from node_eval
                group by NODE
            ),
            inconsistent as (
                select n.NODE, v.IP_ID_PATTERN
                from counts n
                join node_eval v using (NODE)
                where n.pattern_count > 1
            )
            select
                IP_ID_PATTERN,
                count(distinct NODE) as node_count
            from inconsistent
            group by IP_ID_PATTERN
            order by node_count desc
        """).fetchdf()

        # print("\n[Pattern distribution among inconsistent multi-IP nodes]")
        # print(inconsistent_patterns.to_string(index=False))

        # --- Collect all pattern sets for inconsistent nodes ---
        node_patterns = con.execute("""
            with exploded as (
                select NODE, unnest(string_split(IP_LIST, ' ')) as IP
                from node_to_ips
            ),
            filtered as (
                select NODE, count(*) as ip_count
                from exploded
                group by NODE
                having count(*) > 1
            ),
            node_eval as (
                select e.NODE, v.IP_ID_PATTERN
                from exploded e
                join eval v on e.IP = v.IP
                where e.NODE in (select NODE from filtered)
            ),
            counts as (
                select NODE, count(distinct IP_ID_PATTERN) as pattern_count
                from node_eval
                group by NODE
            )
            select NODE, array_agg(distinct IP_ID_PATTERN) as patterns
            from node_eval
            where NODE in (select NODE from counts where pattern_count > 1)
            group by NODE
        """).fetchdf()

        # --- Pairwise pattern combinations ---
        # pair_counter = {}
        # for _, row in node_patterns.iterrows():
        #     patterns = sorted(row["patterns"])
        #     for a, b in itertools.combinations(patterns, 2):
        #         pair = (a, b)
        #         pair_counter[pair] = pair_counter.get(pair, 0) + 1
        #
        # pair_df = pd.DataFrame([
        #     {"Pattern_A": a, "Pattern_B": b, "Nodes": n}
        #     for (a, b), n in sorted(pair_counter.items(), key=lambda x: x[1], reverse=True)
        # ])
        #
        # print("\n[Most common pairwise pattern combinations within inconsistent nodes]")
        # print(pair_df.head(15).to_string(index=False))

        # --- Full pattern sets (without cardinality) ---
        set_counter = {}
        for _, row in node_patterns.iterrows():
            pattern_tuple = tuple(sorted(row["patterns"]))
            set_counter[pattern_tuple] = set_counter.get(pattern_tuple, 0) + 1

        set_df = pd.DataFrame([
            {"Pattern_Set": json.dumps(list(s), ensure_ascii=False), "Nodes": n}
            for s, n in sorted(set_counter.items(), key=lambda x: x[1], reverse=True)
        ])

        print("\n[Full pattern-set combinations]")
        print(set_df.head(15).to_string(index=False))
    elif mode == 13:
        if len(sys.argv) < 4:
            print_usage()
            return
        analyze_traceroute_device_behavior(str(sys.argv[2]), str(sys.argv[3]), t=1, d=0, name="transit-hop")
    elif mode == 14:
        if len(sys.argv) < 4:
            print_usage()
            return
        analyze_traceroute_device_behavior(str(sys.argv[2]), str(sys.argv[3]), t=0, d=1, name="end-device")
    elif mode == 15:
        if len(sys.argv) < 4:
            print_usage()
            return

        plot_distribution(str(sys.argv[2]), str(sys.argv[3]))
    elif mode == 16:
        if len(sys.argv) < 3:
            print_usage()
            return

        msm_path = str(sys.argv[2])

        plot_os_distribution(msm_path, oses, "all")
        plot_os_distribution(msm_path, router, "router")
        plot_os_distribution(msm_path, end_device, "end_device")

        plot_os_pattern_distribution(msm_path, router, "router")
        plot_os_pattern_distribution(msm_path, end_device, "end_device")
    else:
        print_usage()


def plot_os_pattern_distribution(msm_path: str, oses: list[str], ident: str):
    eval_path = os.path.join(msm_path, "eval.csv.zst")
    targets_base_path = os.path.dirname(os.readlink(os.path.join(msm_path, "targets.csv.zst")))
    targets_os_path = os.path.join(targets_base_path, "targets_os.csv.zst")
    analysis_dir = os.path.join(msm_path, "analysis", "os_pattern_distribution", ident)

    print(f"Plotting OS Pattern Distribution for {ident}")

    con = duckdb.connect(database=':memory:')
    con.execute("PRAGMA threads=8;")

    os_filter = ', '.join([f"'{o.lower()}'" for o in oses])
    query = f"""
        SELECT e.IP_ID_PATTERN AS class
        FROM read_csv_auto('{eval_path}') AS e
        JOIN read_csv_auto('{targets_os_path}') AS t
        ON e.IP = t.IP
        WHERE lower(t.OS) IN ({os_filter})
    """

    print("Loading and filtering data via DuckDB...")
    df = con.execute(query).fetch_df()

    print("Computing Pattern Distribution...")
    df = df.value_counts().reset_index()
    df.columns = ['class', 'absolute']
    total = df['absolute'].sum()
    df['relative'] = (df['absolute'] / total) * 100

    full_order = [p.value for p in Pattern]
    df = df[df['relative'] > 0]
    order = [p for p in full_order if p in df['class'].values]

    print(f"Total found IP addresses: {total}")

    print("Plotting Pattern Distribution...")
    plt.figure(figsize=(7, 7))
    ax = sns.barplot(x="class", y="relative", data=df, order=order)
    for container in ax.containers:
        ax.bar_label(container, fmt='%.1f%%', label_type='edge', padding=3, fontsize=16)

    plt.xlabel("Class", fontsize=18)
    plt.xticks(rotation=60, fontsize=16)
    plt.ylabel("Percentage (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(0, 100)
    plt.grid(True, axis="y", linestyle='--', alpha=0.6)
    plt.tight_layout()

    os.makedirs(analysis_dir, exist_ok=True)
    df.to_pickle(os.path.join(analysis_dir, "data.pkl"))
    plt.savefig(os.path.join(analysis_dir, "plot.pdf"), bbox_inches="tight")

    with open(os.path.join(analysis_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total Absolute: {total}\n")
        f.write(f"Class Distribution:\n{df.to_string(index=False)}")

    plt.close()
    con.close()
    print("Done.")


def plot_os_distribution(msm_path: str, oses: list[str], ident: str):
    eval_path = os.path.join(msm_path, "eval.csv.zst")
    targets_base_path = os.path.dirname(os.readlink(os.path.join(msm_path, "targets.csv.zst")))
    targets_os_path = os.path.join(targets_base_path, "targets_os.csv.zst")
    analysis_dir = os.path.join(msm_path, "analysis", "os_distribution", ident)

    print(f"Plotting OS Distribution for {ident}")

    con = duckdb.connect(database=':memory:')
    con.execute("PRAGMA threads=8;")

    os_filter = ', '.join([f"'{o.lower()}'" for o in oses])
    query = f"""
        SELECT lower(t.OS) AS os
        FROM read_csv_auto('{eval_path}') AS e
        JOIN read_csv_auto('{targets_os_path}') AS t
        ON e.IP = t.IP
        WHERE lower(t.OS) IN ({os_filter})
    """

    print("Loading and merging data via DuckDB...")
    df = con.execute(query).fetch_df()

    if df.empty:
        print("No matching OS entries found.")
        return

    print("Computing OS Distribution...")
    df = df.value_counts().reset_index()
    df.columns = ['os', 'absolute']
    total = df['absolute'].sum()
    df['relative'] = (df['absolute'] / total) * 100

    print(f"Total merged IP addresses: {total}")

    print("Plotting OS Distribution...")
    plt.figure(figsize=(len(oses) / 3, 7))
    df_sorted = df.sort_values("relative", ascending=False)
    ax = sns.barplot(x="os", y="relative", data=df_sorted)

    for container in ax.containers:
        labels = [f"{v.get_height():.3f}%\n({int(df_sorted.iloc[i]['absolute'])})" for i, v in enumerate(container)]
        ax.bar_label(container, labels=labels, rotation=90, label_type='edge', padding=3, fontsize=12)

    plt.xlabel("Operating System", fontsize=16)
    plt.xticks(rotation=45, fontsize=12)
    plt.ylabel("Percentage (%)", fontsize=16)
    plt.yticks(fontsize=12)
    plt.grid(True, axis="y", linestyle='--', alpha=0.6)
    plt.tight_layout()

    os.makedirs(analysis_dir, exist_ok=True)
    df.to_pickle(os.path.join(analysis_dir, "data.pkl"))
    plt.savefig(os.path.join(analysis_dir, "plot.pdf"), bbox_inches="tight")

    with open(os.path.join(analysis_dir, "info.txt"), 'w', encoding="utf-8") as f:
        f.write(f"Total IPs: {total}\n")
        f.write(f"OS Distribution:\n{df.to_string(index=False)}")

    plt.close()
    con.close()
    print("Done.")


def analyze_traceroute_device_behavior(caida_itdk_path: str, msm_path: str, t: int, d: int, name: str):
    ip_to_node_file = os.path.join(caida_itdk_path, "ip_to_node.csv.zst")
    eval_file = os.path.join(msm_path, "eval.csv.zst")

    con = duckdb.connect()

    # load compressed CSVs as views
    con.execute(f"""
        create view eval as
        select IP, IP_ID_PATTERN
        from read_csv_auto('{eval_file}', compression='zstd')
    """)
    con.execute(f"""
        create view ip_to_node as
        select IP, T, D
        from read_csv_auto('{ip_to_node_file}', compression='zstd')
    """)
    con.execute(f"""
        create view joined as
        select e.IP_ID_PATTERN
        from eval e
        join ip_to_node m on e.IP = m.IP
        where m.T = {t} and m.D = {d}
    """)

    df_plot = con.execute("""
        select
            IP_ID_PATTERN as class,
            count(*) as absolute
        from joined
        group by IP_ID_PATTERN
    """).df()

    # merge fallback classes if msm_path does not contain "mass"
    if "mass" not in msm_path.lower():
        merged = {}
        for _, row in df_plot.iterrows():
            cls = row["class"]
            if cls in [Pattern.MULTI_GLOBAL.value, Pattern.RANDOM.value, Pattern.FALLBACK.value]:
                merged[Pattern.FALLBACK.value] = merged.get(Pattern.FALLBACK.value, 0) + row["absolute"]
            else:
                merged[cls] = merged.get(cls, 0) + row["absolute"]
        df_plot = pd.DataFrame(list(merged.items()), columns=["class", "absolute"])

    total = df_plot["absolute"].sum()
    df_plot["relative"] = df_plot["absolute"] / total * 100

    # enforce order from Pattern enum
    full_order = [p.value for p in Pattern]
    order = [c for c in full_order if c in df_plot["class"].values]

    # plot
    plt.figure(figsize=(7, 7))
    ax = sns.barplot(
        x="class",
        y="relative",
        data=df_plot[["class", "relative"]],
        order=order
    )
    for container in ax.containers:
        ax.bar_label(container, fmt="%.1f%%", label_type="edge", padding=3, fontsize=16)

    plt.xlabel("Class", fontsize=18)
    plt.xticks(rotation=60, fontsize=16)
    plt.ylabel("Percentage (%)", fontsize=18)
    plt.yticks(fontsize=16)
    plt.ylim(bottom=0, top=100)
    plt.grid(True, axis="y", linestyle="--", alpha=0.6)
    plt.tight_layout()

    # output dir
    target_dir = os.path.join(msm_path, "analysis", f"{name}_pattern_distribution")
    os.makedirs(target_dir, exist_ok=True)

    # save plot
    plt.savefig(os.path.join(target_dir, "plot.pdf"), bbox_inches="tight")
    plt.close()

    # save dataframe and info
    df_plot.to_pickle(os.path.join(target_dir, "data.pkl"))
    with open(os.path.join(target_dir, "info.txt"), "w", encoding="utf-8") as f:
        f.write(f"Total Absolute: {total}\n")
        f.write("Class Distribution:\n")
        f.write(df_plot.to_string(index=False))

    print(f"done, results saved in {target_dir}")


def merge_paths(path_a: str, path_b: str, out_path: str, threads: int = os.cpu_count()):
    os.makedirs(out_path, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"PRAGMA threads={threads};")

    # Targets laden (aus B)
    con.execute(f"""
        CREATE TABLE targets AS
        SELECT IP FROM read_csv_auto('{path_b}/targets.csv.zst', compression='zstd');
    """)

    def merge_file(fname: str):
        # Schema von A bestimmen
        cols = [c[0] for c in con.execute(
            f"DESCRIBE SELECT * FROM read_csv_auto('{path_a}/{fname}', compression='zstd')"
        ).fetchall()]
        cols.remove("IP")  # IP fürs Join nutzen

        # Spaltenliste für SELECT bauen
        select_cols = ["IP"]
        for col in cols:
            if fname == "eval.csv.zst" and col == "IP_ID_PATTERN":
                select_cols.append("""
                    CASE 
                      WHEN t.IP IS NOT NULL AND b.IP IS NULL THEN 'Fallback'
                      ELSE COALESCE(b.IP_ID_PATTERN, a.IP_ID_PATTERN)
                    END AS IP_ID_PATTERN
                """)
            else:
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
              ) b USING(IP)
              LEFT JOIN targets t USING(IP)
              ORDER BY rn
            )
            TO '{out_path}/{fname}' (FORMAT CSV, COMPRESSION ZSTD);
        """
        con.execute(query)

    # probing und eval mergen
    merge_file("probing.csv.zst")
    merge_file("eval.csv.zst")

    con.close()

    # targets.csv.zst von A übernehmen (Symlink oder Datei)
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


def plot_distribution(msm_path: str, name: str):
    # --- Load data ---

    transit_path = os.path.join(msm_path, "analysis", "transit-hop_pattern_distribution", "data.pkl")
    endhost_path = os.path.join(msm_path, "analysis", "end-device_pattern_distribution", "data.pkl")

    with open(Path(transit_path), "rb") as f:
        transit_data = pickle.load(f)
    with open(Path(endhost_path), "rb") as f:
        endhost_data = pickle.load(f)

    # --- Handle DataFrame input ---
    if isinstance(transit_data, pd.DataFrame):
        transit_data = dict(zip(transit_data["class"], transit_data["relative"]))
    if isinstance(endhost_data, pd.DataFrame):
        endhost_data = dict(zip(endhost_data["class"], endhost_data["relative"]))

    # --- Merge all classes that appear in either dataset ---
    all_classes = sorted(set(transit_data.keys()) | set(endhost_data.keys()),
                         key=lambda c: [p.value for p in Pattern].index(c)
                         if c in [p.value for p in Pattern] else 999)

    # --- Extract values safely ---
    transit_values = [float(transit_data.get(c, 0.0)) for c in all_classes]
    endhost_values = [float(endhost_data.get(c, 0.0)) for c in all_classes]

    # --- ACM Plot style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.linewidth": 0.6,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "pdf.fonttype": 42,  # TrueType fonts for ACM
    })

    fig, ax = plt.subplots(figsize=(3.35, 1.6))  # fits double-column width

    x = np.arange(len(all_classes))
    width = 0.38

    ax.bar(x - width / 2, transit_values, width, label="Transit-hops", color="#1f77b4", edgecolor="none")
    ax.bar(x + width / 2, endhost_values, width, label="End-hosts", color="#ff7f0e", edgecolor="none")

    # --- Percentage labels ---
    for i, cls in enumerate(all_classes):
        if transit_values[i] == 0:
            tv = "0.0"
        elif transit_values[i] > 0.1:
            tv = f"{transit_values[i]:.1f}"
        else:
            tv = "<0.1"
        ax.text(x[i] - width / 2, transit_values[i] + 0.5, tv, ha='center', va='bottom', fontsize=6.5)

        if endhost_values[i] == 0:
            ev = "0.0"
        elif endhost_values[i] > 0.1:
            ev = f"{endhost_values[i]:.1f}"
        else:
            ev = "<0.1"
        ax.text(x[i] + width / 2, endhost_values[i] + 0.5, ev, ha='center', va='bottom', fontsize=6.5)

    # --- Labels, grid, and legend ---
    ax.set_ylabel("Percentage [%]", labelpad=1)
    ax.set_xticks(x)
    ax.set_xticklabels(all_classes, rotation=25, ha='center')
    ax.set_ylim(0, max(max(transit_values), max(endhost_values)) * 1.18)
    ax.grid(axis='y', linestyle='--', linewidth=0.4, alpha=0.5)
    ax.legend(frameon=False, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.25))

    # --- Compact layout ---
    plt.tight_layout()

    # --- Save ---
    path = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_distribution.pdf")
    plt.savefig(path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"[+] ACM-style figure saved to {path}")


if __name__ == "__main__":
    main()
