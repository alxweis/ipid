import bz2
import csv
import ipaddress
import json
import math
import os
import pickle
import random
import shutil
import string
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
from matplotlib.ticker import MultipleLocator
from tqdm import tqdm

from analysis.main import plot_response_rate, calc_intersections, intersect_classifications, filter_ips_by_class
from core import EXPERIMENTAL_RESULTS
from core.classifier import pattern_generation_map, chi2_test, Pattern
from experimental.sequence_stable_len_analysis.main import (
    analyze_sequence_stable_lens_synthetic,
    analyze_sequence_stable_lens_natural
)
from hitlist.ip_scan import post_cleanup
from hitlist.os_scan import oses, router, end_device, pretty_oses, os_groups, fallback_color, soft_palette

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
    print("  11 - Merge SEQ and MASS measurement:")
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
    print("  17 - Plot pattern distribution:")
    print(f"    python {filename} 17 <msm_path> <name>")
    print("  18 - Plot time between requests:")
    print(f"    python {filename} 18 <msm_path>")
    print("  19 - Plot random IP-ID sequence classified as specific pattern:")
    print(f"    python {filename} 19 <msm_path> <pattern_name>")
    print("  20 - Plot CAIDA OS distribution:")
    print(f"    python {filename} 20 <caida_itdk_path> <msm_path>")
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

        chi2_inc_result: dict[str, tuple[float, float]] = {}

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

                p_chi2_even_inc = chi2_test(seq.even.increments)
                p_chi2_odd_inc = chi2_test(seq.odd.increments)

                update_range(chi2_inc_result, pattern.value, p_chi2_even_inc, p_chi2_odd_inc)

        def print_results(title: str, results: dict[str, tuple[float, float]]):
            print(f"{title}:")
            for pattern, (_min, _max) in results.items():
                print(f"{pattern}: {_min}...{_max}")
            print()

        print_results("Chi2 Inc Result", chi2_inc_result)
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

        plot_transit_endhost_distribution_acm_style(str(sys.argv[2]), str(sys.argv[3]))
    elif mode == 16:
        if len(sys.argv) < 3:
            print_usage()
            return

        msm_path = str(sys.argv[2])

        # plot_os_distribution(msm_path, oses, "all")
        # plot_os_distribution(msm_path, router, "router")
        # plot_os_distribution(msm_path, end_device, "end_device")

        rhel = (["redhat"], "RHEL")
        ubuntu_debian = (["ubuntu", "debian"], "Ubuntu/Debian")
        windows = (["microsoft", "windows"], "Windows")
        centos = (["centos"], "CentOS")
        fedora = (["fedora"], "Fedora")
        freebsd = (["freebsd"], "FreeBSD")
        openbsd = (["openbsd"], "OpenBSD")

        huawei_vrp = (["huawei"], "Huawei VRP")
        zynos = (["zyxel"], "ZynOS")
        cisco_ios = (["cisco"], "Cisco IOS")
        drayos = (["draytek"], "DrayOS")
        mikrotik_routeros = (["mikrotik"], "MikroTik RouterOS")
        sonicos = (["sonicwall"], "SonicOS")

        # ICMP
        # plot_os_heatmap(msm_path, "general_purpose_os_devices",
        #                 [ubuntu_debian, rhel, centos, fedora, freebsd, openbsd, windows])
        # plot_os_heatmap(msm_path, "network_os_devices",
        #                 [cisco_ios, huawei_vrp, mikrotik_routeros, sonicos, zynos, drayos])

        # TCP/80
        # plot_os_heatmap(msm_path, "general_purpose_os_devices",
        #                 [ubuntu_debian, rhel, centos, fedora, freebsd, openbsd, windows])
        # plot_os_heatmap(msm_path, "network_os_devices",
        #                 [cisco_ios, huawei_vrp, mikrotik_routeros, sonicos, zynos, drayos])

        # UDP/53
        plot_os_heatmap(msm_path, "general_purpose_os_devices",
                        [ubuntu_debian, rhel, centos, fedora, freebsd, openbsd, windows])
        plot_os_heatmap(msm_path, "network_os_devices",
                        [cisco_ios, huawei_vrp, mikrotik_routeros, zynos, drayos])
    elif mode == 17:
        if len(sys.argv) < 5:
            print_usage()
            return

        plot_pattern_distribution_acm_style(str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]))
    elif mode == 18:
        if len(sys.argv) < 3:
            print_usage()
            return

        # plot_time_between_requests_acm_style(str(sys.argv[2]))
        # plot_avg_rtt_per_continent_acm_style(str(sys.argv[2]))
        plot_increment_cdfs_acm_style(str(sys.argv[2]), [Pattern.GLOBAL, Pattern.LOCAL_GE1])
        # plot_increment_cdfs_acm_style(str(sys.argv[2]), [Pattern.MULTI_GLOBAL, Pattern.RANDOM])
    elif mode == 19:
        if len(sys.argv) < 4:
            print_usage()
            return

        msm_path = str(sys.argv[2])
        pattern_name = str(sys.argv[3])
        plot_random_ipid_sequence(msm_path, pattern_name)
    elif mode == 20:
        if len(sys.argv) < 4:
            print_usage()
            return

        plot_caida_os_distribution_acm_style(str(sys.argv[2]), str(sys.argv[3]))
    elif mode == 21:
        if len(sys.argv) < 3:
            print_usage()
            return
        print_constant_pattern_distribution(str(sys.argv[2]))
    elif mode == 22:
        plot_pattern()
    else:
        print_usage()


def print_constant_pattern_distribution(msm_path: str):
    probing_path = os.path.join(msm_path, "probing.csv.zst")
    eval_path = os.path.join(msm_path, "eval.csv.zst")

    con = duckdb.connect()
    con.execute(f"""
        CREATE TEMP TABLE eval AS 
        SELECT * FROM read_csv_auto('{eval_path}', compression='zstd');
        CREATE TEMP TABLE probing AS 
        SELECT * FROM read_csv_auto('{probing_path}', compression='zstd');
    """)

    rows = con.execute("""
        SELECT p.IP_ID_SEQUENCE
        FROM eval e
        JOIN probing p USING (IP)
        WHERE TRIM(e.IP_ID_PATTERN) = 'Constant'
          AND p.IP_ID_SEQUENCE IS NOT NULL
    """).fetchall()

    dist = {}

    for (seq,) in rows:
        vals = list(map(int, seq.split(',')))
        if len(set(vals)) == 1:
            v = vals[0]
            dist[v] = dist.get(v, 0) + 1

    print("Constant IPID group distribution:")
    s = sum(dist.values())
    for k, v in sorted(dist.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{k}: {v} ({v / s * 100:.6f}%)")


def plot_caida_os_distribution_acm_style(caida_itdk_path: str, msm_path: str):
    import duckdb
    import os
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator

    # ------------------------------
    # Mapping: OS → Gruppe oder OS selbst
    # ------------------------------
    def map_os_to_group_or_raw(os_str):
        for group, (members, _) in os_groups.items():
            if os_str in members:
                return group
        return os_str

    # ------------------------------
    # JOIN CAIDA + OS DATA
    # ------------------------------
    ip_to_node_file = os.path.join(caida_itdk_path, "ip_to_node.csv.zst")
    targets_base_path = os.path.dirname(os.readlink(os.path.join(msm_path, "targets.csv.zst")))
    targets_os_file = os.path.join(targets_base_path, "targets_os.csv.zst")

    con = duckdb.connect(database=":memory:")

    con.execute(f"""
        CREATE VIEW ip_to_node AS
        SELECT IP, T, D
        FROM read_csv_auto('{ip_to_node_file}', compression='zstd');
    """)

    con.execute(f"""
        CREATE VIEW targets_os AS
        SELECT IP, OS
        FROM read_csv_auto('{targets_os_file}', compression='zstd');
    """)

    df_joined = con.execute("""
        SELECT n.IP, n.T, n.D, t.OS
        FROM ip_to_node n
        LEFT JOIN targets_os t ON n.IP = t.IP
        WHERE (n.T = 1 AND n.D = 0) OR (n.T = 0 AND n.D = 1)
    """).fetch_df()

    df_joined = df_joined[df_joined["OS"].notna()]
    df_joined["OS"] = df_joined["OS"].astype(str).str.lower()

    # group or raw
    df_joined["LABEL"] = df_joined["OS"].apply(map_os_to_group_or_raw)

    # ------------------------------
    # SAVE CSV
    # ------------------------------
    out_dir = os.path.join(msm_path, "analysis", "caida_os_distribution")
    os.makedirs(out_dir, exist_ok=True)
    df_joined.to_csv(os.path.join(out_dir, "caida_os.csv.zst"), index=False, compression="zstd")

    # ------------------------------
    # DISTRIBUTIONS
    # ------------------------------
    transit = df_joined[(df_joined["T"] == 1) & (df_joined["D"] == 0)]
    endhost = df_joined[(df_joined["T"] == 0) & (df_joined["D"] == 1)]

    print("\n[Transit-Hop IP, OS] (erste 100):")
    for ip, os_ in (
            transit[["IP", "LABEL"]]
                    .drop_duplicates()
                    .head(100)
                    .itertuples(index=False)
    ):
        print(f"[{ip}, {os_}]")

    transit_dist = (transit["LABEL"].value_counts(normalize=True) * 100)
    endhost_dist = (endhost["LABEL"].value_counts(normalize=True) * 100)

    # ------------------------------
    # Reihenfolge:
    # 1) Gruppen
    # 2) zusätzliche OS > 1%
    # ------------------------------
    group_labels = list(os_groups.keys())

    extra_labels = [
        lbl for lbl in sorted(set(df_joined["LABEL"]))
        if lbl not in os_groups and (transit_dist.get(lbl, 0) > 1 or endhost_dist.get(lbl, 0) > 1)
    ]

    # ------------------------------
    # Nur OS Groups / OSes mit >1% aufnehmen
    # ------------------------------
    filtered_labels = []

    # zuerst Gruppen in Reihenfolge behalten, aber nur falls >1%
    for grp in group_labels:
        if transit_dist.get(grp, 0) > 1 or endhost_dist.get(grp, 0) > 1:
            filtered_labels.append(grp)

    # dann zusätzliche OSes >1%
    for lbl in extra_labels:
        if transit_dist.get(lbl, 0) > 1 or endhost_dist.get(lbl, 0) > 1:
            filtered_labels.append(lbl)

    ordered_labels = filtered_labels

    # ------------------------------
    # Farben
    # ------------------------------
    color_map = {}

    # group colors
    for grp, (_, col) in os_groups.items():
        color_map[grp] = col

    # extra colors
    import hashlib

    def stable_index(name, mod):
        h = hashlib.sha1(name.encode("utf-8")).hexdigest()
        x = int(h[:8], 16) % mod
        print(f"{name} : {x}")
        return x

    for lbl in extra_labels:
        color_map[lbl] = soft_palette[stable_index(lbl, len(soft_palette))]

    # ------------------------------
    # Werte für Plot
    # ------------------------------
    transit_values = [transit_dist.get(lbl, 0) for lbl in ordered_labels]
    endhost_values = [endhost_dist.get(lbl, 0) for lbl in ordered_labels]

    # ------------------------------
    # Other-Klasse hinzufügen (Rest zu 100%)
    # ------------------------------
    transit_other = 100 - sum(transit_values)
    endhost_other = 100 - sum(endhost_values)
    ordered_labels.append("Other")
    color_map["Other"] = fallback_color
    pretty_oses["Other"] = "Other"
    transit_values.append(transit_other)
    endhost_values.append(endhost_other)

    # ------------------------------
    # Plot
    # ------------------------------
    # --- ACM Plot style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8.5,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(5.5, 2.0))

    datasets = [transit_values, endhost_values]
    positions = [1, 0]
    names = ["Transit-hops", "End-hosts"]

    for y, values, name in zip(positions, datasets, names):
        left = 0
        for lbl, val in zip(ordered_labels, values):
            ax.barh(y, val, left=left, height=0.45, edgecolor="none", color=color_map[lbl])

            if val >= 1:
                ax.text(left + val / 2, y, str(int(round(val))), ha="center", va="center", fontsize=8)

            left += val

        ax.text(-1, y, name, ha="right", va="center", fontsize=10)

    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 1.5)
    ax.set_xlabel("OS Distribution [%]")

    ax.set_yticks([])
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)
    ax.xaxis.set_minor_locator(MultipleLocator(5))

    legend_handles = [
        plt.Line2D([0], [0], color=color_map[lbl], lw=4)
        for lbl in ordered_labels
    ]
    legend_labels = [
        pretty_oses.get(lbl, lbl)
        for lbl in ordered_labels
    ]

    ax.legend(
        legend_handles,
        legend_labels,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        ncol=int(math.ceil(len(legend_labels) / 2)),
        frameon=False,
        handletextpad=0.4,
        borderaxespad=0.2
    )

    plt.tight_layout()

    out_file = os.path.join(out_dir, "os_distribution_acm_style.pdf")
    plt.savefig(out_file, format="pdf", bbox_inches="tight")
    plt.close(fig)

    print(f"[+] CAIDA OS distribution saved to {out_file}")

    # ------------------------------
    # METADATA EXPORT
    # ------------------------------

    info_path = os.path.join(out_dir, "info.txt")

    with open(info_path, "w") as f:
        f.write("CAIDA OS Distribution Metadata\n")
        f.write("=====================================\n\n")

        f.write(f"Total Transit-hops: {len(transit)}\n")
        f.write(f"Total End-hosts:    {len(endhost)}\n\n")

        f.write("Per-OS Statistics (absolute and percentage)\n")
        f.write("--------------------------------------------------\n")

        # absolute counts
        transit_abs = transit["LABEL"].value_counts()
        endhost_abs = endhost["LABEL"].value_counts()

        for lbl in ordered_labels:
            abs_t = transit_abs.get(lbl, 0)
            abs_e = endhost_abs.get(lbl, 0)

            pct_t = transit_dist.get(lbl, 0)
            pct_e = endhost_dist.get(lbl, 0)

            if lbl == "Other":
                pct_t = transit_other
                pct_e = endhost_other

            f.write(
                f"{lbl}:\n"
                f"  Transit:  {abs_t}  ({pct_t:.2f}%)\n"
                f"  End-host: {abs_e}  ({pct_e:.2f}%)\n\n"
            )


def plot_random_ipid_sequence(msm_path: str, pattern_name: str, count: int = 10):
    probing_path = os.path.join(msm_path, "probing.csv.zst")
    eval_path = os.path.join(msm_path, "eval.csv.zst")

    con = duckdb.connect()
    con.execute(f"""
        CREATE TEMP TABLE eval AS 
        SELECT * FROM read_csv_auto('{eval_path}', compression='zstd');
        CREATE TEMP TABLE probing AS 
        SELECT * FROM read_csv_auto('{probing_path}', compression='zstd');
    """)

    for i in range(count):
        # Seed zwischen -1.0 und 1.0 (DuckDB akzeptiert nur diesen Bereich)
        seed = random.uniform(-1.0, 1.0)
        con.execute(f"SELECT setseed({seed});")

        row = con.execute(f"""
            SELECT IP 
            FROM eval 
            WHERE TRIM(IP_ID_PATTERN) = '{pattern_name}'
            ORDER BY RANDOM()
            LIMIT 1
        """).fetchone()

        if not row:
            print(f"No entries found for pattern '{pattern_name}'")
            return

        ip = row[0]
        seq_row = con.execute(f"""
            SELECT IP_ID_SEQUENCE 
            FROM probing 
            WHERE IP = '{ip}'
        """).fetchone()

        if not seq_row or not seq_row[0]:
            print(f"No IPID sequence found for IP {ip}")
            continue

        seq = seq_row[0]
        y = list(map(int, seq.split(',')))

        # neuer Plot pro IP
        plt.figure()
        plt.plot(range(1, len(y) + 1), y, marker='o')
        plt.xlabel("Index")
        plt.ylabel("IPID Value")
        plt.title(f"{pattern_name} – {ip}")
        plt.grid(True)

        print(f"{ip} : {seq}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = ''.join(random.choices(string.ascii_lowercase, k=3))
        fn = f"plot_{pattern_name.replace(' ', '_')}_{timestamp}_{suffix}.png"
        plt.savefig(fn, dpi=200, bbox_inches="tight")
        plt.close()
        print(f"Plot saved as {fn}")


def plot_os_heatmap(msm_path: str, ident: str, os_groups: list[tuple[list[str], str]]):
    eval_path = os.path.join(msm_path, "eval.csv.zst")
    targets_base_path = os.path.dirname(os.readlink(os.path.join(msm_path, "targets.csv.zst")))
    targets_os_path = os.path.join(targets_base_path, "targets_os.csv.zst")
    analysis_dir = os.path.join(msm_path, "analysis", "os_heatmap", ident)

    print(f"Plotting ACM-style OS Heatmap for {ident}")

    con = duckdb.connect(database=':memory:')
    con.execute("PRAGMA threads=8;")

    os_conditions = []
    for os_list, label in os_groups:
        for name in os_list:
            os_conditions.append(f"WHEN lower(t.OS) = '{name.lower()}' THEN '{label}'")
    os_case = " ".join(os_conditions)

    query = f"""
        SELECT e.IP_ID_PATTERN AS class,
               CASE {os_case} ELSE 'Other' END AS os_group
        FROM read_csv_auto('{eval_path}') AS e
        JOIN read_csv_auto('{targets_os_path}') AS t
        ON e.IP = t.IP
    """

    df = con.execute(query).fetch_df()
    # df = df[df["os_group"] != "Other"]

    pivot = df.value_counts().reset_index()
    pivot.columns = ["class", "os_group", "count"]
    pivot_table = pivot.pivot(index="os_group", columns="class", values="count").fillna(0)

    # Absolute Summen pro OS
    pivot_table["Total"] = pivot_table.sum(axis=1)
    # pivot_table = pivot_table.sort_values("Total", ascending=False)

    # Reihenfolge gemäß os_groups erzwingen
    desired_order = []
    for os_list, label in os_groups:
        if label in pivot_table.index:
            desired_order.append(label)

    # Other immer ans Ende hängen, falls vorhanden
    if "Other" in pivot_table.index:
        desired_order.append("Other")

    # Nur OS-Gruppen behalten, die vorkommen
    pivot_table = pivot_table.loc[desired_order]

    # Sortierung der Spalten
    pattern_order = [p.value for p in Pattern if p.value in pivot_table.columns]
    pivot_table = pivot_table[pattern_order + ["Total"]]

    # Relative Werte
    pivot_table_rel = pivot_table.div(pivot_table["Total"], axis=0) * 100
    pivot_table_rel = pivot_table_rel.drop(columns=["Total"])

    # ACM CCR Stil mit etwas größerer Schrift
    plt.rcParams.update({
        "font.family": "Times New Roman",
        "font.size": 11,
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
    })

    plt.figure(figsize=(5.0, 2.5))
    ax = sns.heatmap(
        pivot_table_rel,
        annot=True,
        fmt=".1f",
        cmap="Blues",
        cbar_kws={'label': 'Percentage [%]'},
        linewidths=0.4,
        linecolor='white'
    )

    # OS Labels mit Total Count
    # os_labels = [f"{os_name}" for os_name, total in zip(pivot_table.index, pivot_table["Total"])]
    def fmt_count(n):
        if n >= 1_000_000:
            return f"{n / 1_000_000:.1f}M"
        if n >= 100_000:
            return f"{int(n / 1000)}k"
        if n >= 10_000:
            return f"{int(n / 1000)}k"
        if n >= 1000:
            return f"{n / 1000:.1f}k"
        return str(int(n))

    os_labels = [
        f"{os_name} ({fmt_count(total)})"
        for os_name, total in zip(pivot_table.index, pivot_table["Total"])
    ]
    ax.set_yticklabels(os_labels, rotation=0)

    # Achsenbeschriftungen
    plt.xlabel("Class", labelpad=4)
    plt.ylabel("OS Group (#IP Addr.)", labelpad=4)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=25, ha="right")

    # Rand um Heatmap
    for _, spine in ax.spines.items():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_color("black")

    plt.tight_layout(pad=0.4)

    os.makedirs(analysis_dir, exist_ok=True)
    pivot_table_rel.to_pickle(os.path.join(analysis_dir, "data.pkl"))
    plt.savefig(os.path.join(analysis_dir, "plot.pdf"), bbox_inches="tight", dpi=300)

    # Info-Datei mit absoluten und relativen Werten
    with open(os.path.join(analysis_dir, "info.txt"), "w", encoding="utf-8") as f:
        f.write("=== Absolute Counts (including Totals) ===\n")
        f.write(pivot_table.to_string(float_format=lambda x: f"{int(x)}"))
        f.write("\n\n=== Relative Percentages ===\n")
        f.write(pivot_table_rel.to_string(float_format=lambda x: f"{x:.1f}%"))

    plt.close()
    con.close()
    print("Done.")


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


def plot_pattern():
    patterns = ["Global Ctr.", "Per-Dest. Ctr.", "Per-Conn. Ctr.", "Per-Bucket Ctr.", "PRNG-based"]
    counts = [19, 6, 7, 9, 1]

    dist = {
        "Global Ctr.": (4, 14, 7),
        "Per-Bucket Ctr.": (0, 7, 3),
        "Per-Conn. Ctr.": (0, 5, 2),
        "Per-Dest. Ctr.": (0, 3, 4),
        "PRNG-based": (0, 0, 1),
    }

    # --- Sortieren nach counts (absteigend) ---
    data = list(zip(patterns, counts))
    data.sort(key=lambda x: x[1], reverse=True)
    patterns, counts = zip(*data)

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8.5,
        "pdf.fonttype": 42,
    })

    plt.figure(figsize=(4.0, 2.0))
    plt.gca().invert_yaxis()

    left = np.zeros(len(counts))
    colors = ["tab:red", "tab:green", "tab:blue"]
    labels = ["ICMP", "TCP", "UDP"]

    for i, proto in enumerate(labels):
        values = [counts[j] * dist[patterns[j]][i] / sum(dist[patterns[j]]) for j in range(len(patterns))]
        bars = plt.barh(patterns, values, left=left, color=colors[i], label=proto)

        for y, (bar, pattern) in enumerate(zip(bars, patterns)):
            val = dist[pattern][i]
            if val > 0:
                plt.text(
                    left[y] + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2,
                    f"{val}",
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white"
                )

        left += values

    # --- Gesamtzahl rechts ---
    for y, c in enumerate(counts):
        plt.text(c + 0.2, y, f"{c}", va="center", fontsize=9)

    plt.xlabel("#Papers exploiting the IP-ID method")
    plt.ylabel("IP-ID method")
    plt.legend(frameon=False, ncol=3, loc="lower right")

    # ax = plt.gca()
    # ax.xaxis.set_minor_locator(AutoMinorLocator())
    # ax.tick_params(axis="x", which="major", length=6)
    # ax.tick_params(axis="x", which="minor", length=3)

    plt.margins(x=0.15)
    plt.tight_layout()
    plt.savefig("ipid_papers.pdf", bbox_inches="tight")


def plot_pattern_distribution_acm_style(msm_path_1: str, msm_path_2: str, name: str):
    def load_data(msm_path):
        data_path = os.path.join(msm_path, "analysis", "pattern_distribution", "data.pkl")
        with open(Path(data_path), "rb") as f:
            data = pickle.load(f)
        if isinstance(data, pd.DataFrame):
            data = dict(zip(data["class"], data["relative"]))
        return data

    # --- Load both datasets ---
    data1 = load_data(msm_path_1)
    data2 = load_data(msm_path_2)

    # --- Sort classes nach Pattern Enum ---
    all_classes = sorted(
        set(data1.keys()).union(data2.keys()),
        key=lambda c: [p.value for p in Pattern].index(c)
        if c in [p.value for p in Pattern] else 999
    )

    values1 = [float(data1.get(c, 0.0)) for c in all_classes]
    values2 = [float(data2.get(c, 0.0)) for c in all_classes]

    # --- Farbzuordnung ---
    color_map = {
        "Mirror": "#FFE866",
        "Constant": "#6FB8FF",
        "Single": "#FF8080",
        "Per-Dst": "#B580FF",
        "Per-Con": "#B550FF",
        "Per-Bucket": "#6EE66E",
        "Per-CPU": "#66E0E0",
        "Random": "#FFB266",
        "Fallback": "#A0A0A0"
    }

    # --- ACM Plot style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8.5,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(5.5, 2.0))

    y_positions = [1, 0]
    datasets = [values1, values2]
    labels = ["1", "2"]

    bars = []
    fallback_start = fallback_end = 0
    width = 0.45

    for y, values, label in zip(y_positions, datasets, labels):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = color_map.get(cls, "#CCCCCC")
            bar = ax.barh(y, val, left=left, height=width,
                          edgecolor="none", color=color)
            current_bars.append(bar)

            # --- Prozentwerte ab 5%, ganzzahlig gerundet ---
            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",  # <-- ganze Zahl
                    ha="center", va="center",
                    color="black", fontsize=8
                )

            left += val

            if y == 1 and cls == "Fallback":
                fallback_start = left - val
                fallback_end = left

        ax.text(-1, y, label, ha="right", va="center", fontsize=10)
        bars = current_bars

    # --- Gestrichelte Linien & Fläche ---
    ax.plot([fallback_start, 0],
            [(1 - width) + width * 0.5, width * 0.5],
            color='gray', linestyle='--', linewidth=0.8, alpha=0.5)

    ax.plot([fallback_end, 100],
            [(1 - width) + width * 0.5, width * 0.5],
            color='gray', linestyle='--', linewidth=0.8, alpha=0.5)

    ax.fill_betweenx(
        [(1 - width) + width * 0.5, width * 0.5],
        [fallback_start, 0],
        [fallback_end, 100],
        color='lightgray', alpha=0.5
    )

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 1.5)
    ax.set_xlabel("IP-ID Class Distribution [%]", labelpad=2)

    # --- MINORTICKS aktivieren ---
    ax.xaxis.set_minor_locator(MultipleLocator(5))  # alle 5%
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    fig.text(0.01, 0.5, "Measurement [Index]",
             va="center", ha="center", rotation="vertical", fontsize=10)

    ax.set_yticks([])
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    # --- Legende ---
    ax.legend(
        [b[0] for b in bars],
        all_classes,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        ncol=4,
        frameon=False,
        handletextpad=0.4,
        borderaxespad=0.2
    )

    plt.tight_layout()

    path = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_pattern_distribution.pdf")
    plt.savefig(path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Combined horizontal stacked bar plot saved to {path}")


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
    if "seq" in msm_path.lower():
        merged = {}
        for _, row in df_plot.iterrows():
            cls = row["class"]
            if cls in [Pattern.PER_CPU.value, Pattern.RANDOM.value, Pattern.FALLBACK.value]:
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
    # if os.path.lexists(dst):
    #     os.remove(dst)
    if os.path.islink(src):
        target = os.readlink(src)
        os.symlink(target, dst)
    else:
        shutil.copy(src, dst)

    print(f"Merged {path_a} & {path_b} => {out_path}")
    print(f"Rerun analysis of {out_path} to get merged results!")


def plot_transit_endhost_distribution_acm_style(msm_path: str, name: str):
    # --- Load data ---
    transit_path = os.path.join(msm_path, "analysis", "transit-hop_pattern_distribution", "data.pkl")
    endhost_path = os.path.join(msm_path, "analysis", "end-device_pattern_distribution", "data.pkl")

    with open(Path(transit_path), "rb") as f:
        transit_data = pickle.load(f)
    with open(Path(endhost_path), "rb") as f:
        endhost_data = pickle.load(f)

    # --- Normalize DataFrame input ---
    if isinstance(transit_data, pd.DataFrame):
        transit_data = dict(zip(transit_data["class"], transit_data["relative"]))
    if isinstance(endhost_data, pd.DataFrame):
        endhost_data = dict(zip(endhost_data["class"], endhost_data["relative"]))

    # --- Sort classes ---
    all_classes = sorted(
        set(transit_data.keys()).union(endhost_data.keys()),
        key=lambda c: [p.value for p in Pattern].index(c)
        if c in [p.value for p in Pattern] else 999
    )

    transit_values = [float(transit_data.get(c, 0.0)) for c in all_classes]
    endhost_values = [float(endhost_data.get(c, 0.0)) for c in all_classes]

    # --- Farbzuordnung (wie bisher) ---
    color_map = {
        "Mirror": "#FFE866",
        "Constant": "#6FB8FF",
        "Single": "#FF8080",
        "Per-Dst": "#B580FF",
        "Per-Bucket": "#6EE66E",
        "Per-CPU": "#66E0E0",
        "Random": "#FFB266",
        "Fallback": "#A0A0A0"
    }

    # --- ACM Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 8.5,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(5.5, 2.0))

    y_positions = [1, 0]
    data_sets = [transit_values, endhost_values]
    labels = ["Transit-hops", "End-hosts"]

    bars = []
    width = 0.45

    for y, values, ylabel in zip(y_positions, data_sets, labels):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = color_map.get(cls, "#CCCCCC")

            bar = ax.barh(
                y, val, left=left, height=width,
                edgecolor="none", color=color
            )
            current_bars.append(bar)

            # Prozentwerte ganzzahlig, ab 1 %
            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",
                    ha="center", va="center",
                    fontsize=8, color="black"
                )

            left += val

        ax.text(-1, y, ylabel, ha="right", va="center", fontsize=10)
        bars = current_bars

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 1.5)
    ax.set_xlabel("IP-ID Class Distribution [%]")

    # Minorticks (5 %)
    ax.xaxis.set_minor_locator(MultipleLocator(5))
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    # fig.text(
    #     0.01, 0.5, "Category",
    #     va="center", ha="center",
    #     rotation="vertical", fontsize=10
    # )

    ax.set_yticks([])
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    # --- Legende ---
    ax.legend(
        [b[0] for b in bars],
        all_classes,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        ncol=4,
        frameon=False,
        handletextpad=0.4,
        borderaxespad=0.2
    )

    plt.tight_layout()

    output_dir = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_transit_endhost_distribution.pdf")
    plt.savefig(output_dir, format="pdf", bbox_inches="tight")
    plt.close(fig)

    print(f"[+] Transit/Endhost ACM-style distribution saved to {output_dir}")


def plot_time_between_requests_acm_style(msm_path: str):
    # --- Load data (.npy) ---
    data_path = os.path.join(msm_path, "analysis", "time_between_requests", "data.npy")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found: {data_path}")

    deltas = np.load(data_path)

    # --- Cut extremes (99.9 percentile) ---
    q = np.percentile(deltas, (99.9 / 99.9) * 100)
    deltas = deltas[deltas <= q]

    # --- ACM CCR Plot style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.linewidth": 0.6,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(2.35, 1.6))

    sns.histplot(
        deltas,
        bins=50,
        stat="percent",
        color="#1f77b4",
        ax=ax,
        linewidth=0.2,
        edgecolor="white"
    )

    # --- Labels and layout ---
    ax.set_xlabel("Time between Requests [ms]")
    ax.set_ylabel("Relative Frequency [%]")
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.grid(True, linestyle="--", linewidth=0.4, alpha=0.5)
    ax.tick_params(width=0.4, length=2)

    # --- Frame and style tweaks for ACM look ---
    for spine in ax.spines.values():
        spine.set_linewidth(0.5)
        spine.set_color("black")

    plt.tight_layout(pad=0.2)

    # --- Save ---
    output_dir = os.path.join(msm_path, "analysis", "time_between_requests")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "plot_acm_style.pdf")

    plt.savefig(output_file, format="pdf", bbox_inches="tight", dpi=600)
    plt.close(fig)

    print(f"[+] ACM-style compact figure saved to {output_file}")


def plot_avg_rtt_per_continent_acm_style(msm_path: str):
    # --- Load data ---
    data_path = os.path.join(msm_path, "analysis", "rtt_per_continent", "data.pkl")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found: {data_path}")

    df = pd.read_pickle(data_path)

    df["continent"] = df["continent"].replace({
        "North America": "N.America",
        "South America": "S.America",
    })

    df = df.groupby("continent").apply(
        lambda g: g[g["rtts"] <= g["rtts"].quantile(0.995 / 0.999)]
    ).reset_index(drop=True)

    # --- Compute order by sample count ---
    df_counts = df["continent"].value_counts()
    order = df_counts.index.tolist()

    # --- ACM CCR Plot style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.linewidth": 0.6,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(2.6, 1.7))

    sns.violinplot(
        data=df,
        x="continent",
        y="rtts",
        order=order,
        inner="quartile",
        density_norm="width",  # <- ersetzt 'scale="width"'
        linewidth=0.45,
        cut=0,
        color="#1f77b4",
        ax=ax
    )

    # --- Labels and layout ---
    ax.set_xlabel("")
    ax.set_ylabel("Average RTT [ms]")
    ax.set_ylim(bottom=0)

    # Ticks klarer setzen (fixiert -> verhindert Warning)
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels(order, rotation=0, ha="center")

    # --- Grid & style ---
    ax.grid(True, axis="y", linestyle="--", linewidth=0.4, alpha=0.5)
    ax.tick_params(width=0.4, length=2)

    # Schwarzer Rand um Plot
    for spine in ax.spines.values():
        spine.set_linewidth(0.5)
        spine.set_color("black")

    plt.tight_layout(pad=0.3)

    # --- Save ---
    output_dir = os.path.join(msm_path, "analysis", "rtt_per_continent")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "plot_acm_style.pdf")

    plt.savefig(output_file, format="pdf", bbox_inches="tight", dpi=600)
    plt.close(fig)

    print(f"[+] ACM-style RTT violin plot saved to {output_file}")


def plot_increment_cdfs_acm_style(msm_path: str, patterns: list[Pattern]):
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.linewidth": 0.6,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "pdf.fonttype": 42,
    })

    # kompakteres Format: etwas breiter, weniger hoch
    fig, ax = plt.subplots(figsize=(2.45, 1.25))
    colors = plt.cm.tab10.colors

    for i, pattern in enumerate(patterns):
        data_path = os.path.join(
            msm_path,
            "analysis",
            "inc_distribution",
            pattern.value.lower().replace(" ", ""),
            "data.npy"
        )
        if not os.path.exists(data_path):
            print(f"[!] Skipping {pattern}: no data file found.")
            continue

        increments = np.load(data_path)
        if len(increments) == 0:
            print(f"[!] Skipping {pattern}: empty data.")
            continue

        # 99.9%-Cut für Ausreißer
        q = np.percentile(increments, (99.9 / 99.9) * 100)
        increments = increments[increments <= q]

        sorted_vals = np.sort(increments)
        cdf = np.arange(1, len(sorted_vals) + 1) / len(sorted_vals) * 100

        ax.step(
            sorted_vals,
            cdf,
            where="post",
            label=pattern.value,
            linewidth=0.55,
            color=colors[i % len(colors)]
        )

    # --- Achsen / Layout ---
    ax.set_xscale("log")
    ax.set_xlim(left=1)
    ax.set_ylim(0, 102)
    ax.yaxis.set_minor_locator(plt.MultipleLocator(25))
    ax.set_xlabel("IP-ID Increment")
    ax.set_ylabel("Cum. Percentage [%]")

    # kompaktere Achsen-Ticks
    ax.tick_params(axis='x', which='major', length=2.5, width=0.35)
    ax.tick_params(axis='x', which='minor', length=1.2, width=0.3)
    ax.tick_params(axis='y', which='major', length=2.5, width=0.35)
    ax.tick_params(axis='y', which='minor', length=1.2, width=0.3)

    ax.grid(True, linestyle="--", linewidth=0.3, alpha=0.45)

    for spine in ax.spines.values():
        spine.set_linewidth(0.45)

    # Sehr kompakte Legende
    ax.legend(
        frameon=False,
        fontsize=6,
        loc="lower right",
        handlelength=1.05,
        borderpad=0.15,
        labelspacing=0.1
    )

    plt.tight_layout(pad=0.1)

    output_dir = os.path.join(msm_path, "analysis", "inc_distribution")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "plot_cdf_multi_acm_style.pdf")

    plt.savefig(output_file, format="pdf", bbox_inches="tight", dpi=600)
    plt.close(fig)

    print(f"[+] Multi-pattern ACM-style CDF saved to {output_file}")


if __name__ == "__main__":
    main()
