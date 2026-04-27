import bz2
import csv
import hashlib
import ipaddress
import json
import math
import os
import pickle
import random
import shutil
import string
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import duckdb
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import zstandard as zstd
from matplotlib.collections import PolyCollection
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.ticker import MultipleLocator, NullFormatter

from analysis.main import plot_response_rate, calc_intersections, intersect_classifications, filter_ips_by_class
from core import EXPERIMENTAL_RESULTS, TEST_RESULTS
from core.classifier import pattern_generation_map, chi2_test, Pattern, IPIDSequence, get_pattern, nist_test
from experimental.sequence_stable_len_analysis.main import (
    analyze_sequence_stable_lens_synthetic,
    analyze_sequence_stable_lens_natural
)
from hitlist.ip_scan import post_cleanup
from hitlist.os_scan import pretty_oses, os_groups, fallback_color, soft_palette
from postproc import GEOLITE_COUNTRY_DB

filename = os.path.basename(__file__)

white_blues = LinearSegmentedColormap.from_list(
    "white_blues",
    [
        (0.000, "#FFFFFF"),
        (0.125, "#DEEBF7"),
        (0.250, "#C6DBEF"),
        (0.375, "#9ECAE1"),
        (0.500, "#6BAED6"),
        (0.625, "#4292C6"),
        (0.750, "#2171B5"),
        (0.875, "#08519C"),
        (1.000, "#08306B"),
    ],
)


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

        tmp_dir = caida_itdk_path

        tmp_ifaces = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", dir=tmp_dir).name
        tmp_nodes = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", dir=tmp_dir).name

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
        force_create_dataset = False
        reclassify_dataset = False
        sequence_count_per_pattern = 100_000
        run_cdf(sequence_length=sequence_length,
                sequence_count_per_pattern=sequence_count_per_pattern,
                force_create_dataset=force_create_dataset,
                reclassify_dataset=reclassify_dataset,
                close_range=False,
                test="chi2"
                )
        run_cdf(sequence_length=sequence_length,
                sequence_count_per_pattern=sequence_count_per_pattern,
                force_create_dataset=force_create_dataset,
                reclassify_dataset=reclassify_dataset,
                close_range=False,
                test="nist"
                )
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
        analyze_traceroute_device_behavior(str(sys.argv[2]), str(sys.argv[3]), t=1, d=None, name="transit-hop")
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
        ubuntu = (["ubuntu"], "Ubuntu")
        debian = (["debian"], "Debian")
        windows = (["microsoft", "windows"], "Microsoft Windows")
        centos = (["centos"], "CentOS")
        fedora = (["fedora"], "Fedora")
        freebsd = (["freebsd"], "FreeBSD")
        openbsd = (["openbsd"], "OpenBSD")

        huawei_vrp = (["huawei"], "Huawei VRP")
        zynos = (["zyxel"], "Zyxel ZynOS")
        cisco_ios = (["cisco"], "Cisco IOS")
        # drayos = (["draytek"], "DrayOS")
        mikrotik_routeros = (["mikrotik"], "MikroTik RouterOS")
        sonicos = (["sonicwall"], "SonicOS")

        # ICMP
        if "icmp" in msm_path:
            plot_os_heatmap(msm_path, "general_purpose_os_devices",
                            [ubuntu, debian, rhel, centos, fedora, freebsd, openbsd, windows])
            plot_os_heatmap(msm_path, "network_os_devices",
                            [cisco_ios, huawei_vrp, mikrotik_routeros, sonicos, zynos])  # drayos

        # TCP/80
        if "tcp" in msm_path:
            plot_os_heatmap(msm_path, "general_purpose_os_devices",
                            [ubuntu, debian, rhel, centos, fedora, freebsd, openbsd, windows])
            plot_os_heatmap(msm_path, "network_os_devices",
                            [cisco_ios, huawei_vrp, mikrotik_routeros, sonicos, zynos])  # drayos

        # UDP/53
        if "udp" in msm_path:
            plot_os_heatmap(msm_path, "general_purpose_os_devices",
                            [ubuntu, debian, rhel, centos, fedora, freebsd, openbsd, windows])
            plot_os_heatmap(msm_path, "network_os_devices",
                            [cisco_ios, huawei_vrp, mikrotik_routeros, zynos])  # drayos

        plot_os_heatmap_combined(
            msm_path,
            idents=[
                ("general_purpose_os_devices", "General-Purpose OS"),
                ("network_os_devices", "Network OS"),
            ],
            name="os_heatmap_combined",
        )
    elif mode == 17:
        if len(sys.argv) < 5:
            print_usage()
            return

        plot_pattern_distribution_acm_style_old(str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]))
    elif mode == 18:
        if len(sys.argv) < 3:
            print_usage()
            return

        # plot_time_between_requests_acm_style(str(sys.argv[2]))
        # plot_avg_rtt_per_continent_acm_style(str(sys.argv[2]))
        # patterns = [Pattern.REFLECTION, Pattern.CONSTANT, Pattern.GLOBAL, Pattern.PER_DST,
        #             Pattern.PER_CON, Pattern.PER_BUCKET, Pattern.PER_CPU, Pattern.RANDOM]
        patterns = [Pattern.GLOBAL, Pattern.PER_DST, Pattern.PER_CON, Pattern.PER_BUCKET, Pattern.PER_CPU, Pattern.RANDOM]
        plot_increment_cdfs_acm_style(str(sys.argv[2]), patterns)
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
    elif mode == 23:
        # python3 X_experimental.py 23 caida merge seq mass proto
        if len(sys.argv) < 7:
            print_usage()
            return

        caida = sys.argv[2]
        merge = sys.argv[3]
        seq = sys.argv[4]
        mass = sys.argv[5]
        proto = sys.argv[6]

        script = sys.argv[0]

        def run_sequential(params):
            params = [str(p) for p in params]
            subprocess.run([sys.executable, script] + params)

        runs = [
            ["13", caida, merge],
            ["14", caida, merge],
            ["15", merge, proto],
            ["16", merge],
            ["17", seq, mass, proto],
            ["20", caida, merge],
            ["21", merge],
        ]

        for r in runs:
            run_sequential(r)
    elif mode == 24:
        if len(sys.argv) < 3:
            print_usage()
            return

        msm_path = str(sys.argv[2])
        filter_probing_by_targets(msm_path)
    elif mode == 25:
        if len(sys.argv) < 5:
            print_usage()
            return

        merge_eval_with_rst(msm_path=str(sys.argv[2]), rst_path=str(sys.argv[3]), class_filter=str(sys.argv[4]))
    elif mode == 26:
        if len(sys.argv) < 3:
            print_usage()
            return

        classify_first_four_for_per_con(msm_path=str(sys.argv[2]))
    elif mode == 27:
        if len(sys.argv) < 6:
            print_usage()
            return

        plot_pattern_distribution_acm_style(str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]), str(sys.argv[5]))
    elif mode == 28:
        if len(sys.argv) < 6:
            print_usage()
            return

        plot_pattern_distribution_acm_style_rst(str(sys.argv[2]), str(sys.argv[3]), str(sys.argv[4]), str(sys.argv[5]))
    elif mode == 29:
        if len(sys.argv) < 3:
            print_usage()
            return

        targets_file = os.path.join(str(sys.argv[2]), "targets.csv.zst")
        sample_targets(targets_file)
    elif mode == 30:
        if len(sys.argv) < 4:
            print_usage()
            return

        msm_path_seq = str(sys.argv[2])
        msm_path_mass = str(sys.argv[3])

        plot_rtt_per_region_acm(msm_path_seq, msm_path_mass)
    else:
        print_usage()


def plot_rtt_per_region_acm(msm_path_seq: str, msm_path_mass: str,
                            max_samples_per_group: int = 500_000):
    """
    Plottet einen Split-Violin der RTT-Verteilungen (Inter-Send-Abstände) pro
    Kontinent für zwei Messungen (SEQ vs MASS).

    :param msm_path_seq:   Pfad zur sequentiellen Messung (probing.csv.zst).
    :param msm_path_mass:  Pfad zur Mass-Messung (probing.csv.zst).
    :param max_samples_per_group: Anzahl Samples pro (Kontinent, Source) für den Plot.
                                  Statistiken in info.txt nutzen weiterhin den vollen Datensatz.
    """
    # --- Pfade ---
    if "icmp" in msm_path_seq:
        prefix = "icmp"
    elif "tcp" in msm_path_seq:
        prefix = "tcp"
    elif "udp" in msm_path_seq:
        prefix = "udp"
    else:
        raise Exception("No protocol found")

    if "connection" in msm_path_seq:
        prefix = f"{prefix}_connection"

    out_dir = os.path.join(EXPERIMENTAL_RESULTS, f"{prefix}_rtt_per_region_combined")
    os.makedirs(out_dir, exist_ok=True)
    cache_fp = os.path.join(out_dir, "rtts_per_continent.parquet")
    plot_fp = os.path.join(out_dir, "plot_acm_style.pdf")
    info_fp = os.path.join(out_dir, "info.txt")

    # --- RTT-Daten extrahieren (mit Cache) ---
    force_create_dataset = False
    if os.path.exists(cache_fp) and not force_create_dataset:
        print(f"Loading cached RTTs from {cache_fp}")
        df = pd.read_parquet(cache_fp)
    else:
        print("Extracting RTTs from probing CSVs...")
        df_seq = _extract_rtts_with_continent(msm_path_seq, label="SEQ")
        df_mass = _extract_rtts_with_continent(msm_path_mass, label="MASS")
        df = pd.concat([df_seq, df_mass], ignore_index=True)
        df.to_parquet(cache_fp, compression="zstd")
        print(f"Cached RTT dataset to {cache_fp} ({len(df):,} rows)")

    # --- Kontinente filtern (None/Antarctica raus) ---
    df = df[~df["continent"].isin(["None", "Antarctica"])]

    # --- Labels mit #IPs pro Kontinent (unique IPs über beide Messungen) ---
    ip_counts = df.dropna(subset=["ip"]).groupby("continent")["ip"].nunique().to_dict()

    # --- Kontinente mit 0 IPs entfernen ---
    valid_continents = [c for c, n in ip_counts.items() if n > 0]
    df = df[df["continent"].isin(valid_continents)]

    # --- Reihenfolge: nach Sample-Count (descending) ---
    order = df["continent"].value_counts().index.tolist()

    # --- Downsampling für den Plot (Statistik bleibt full-scale) ---
    print(f"Downsampling to max {max_samples_per_group:,} per (continent, source)...")
    df_plot = (
        df.groupby(["continent", "source"], group_keys=False)
        .apply(lambda g: g.sample(min(len(g), max_samples_per_group), random_state=42))
    )

    # --- Auf 99.5-Perzentil clippen (entfernt extreme Tails für Plot) ---
    df_plot = (
        df_plot.groupby(["continent", "source"], group_keys=False)
        .apply(lambda g: g[g["rtt_ms"] <= g["rtt_ms"].quantile(0.995)])
    )
    print(f"Plot dataset after P99.5 clip: {len(df_plot):,} rows")

    # --- Nach Filterung & Clipping: nur Kontinente behalten, die in BEIDEN
    # Sources mit ausreichend Samples vertreten sind ---
    MIN_SAMPLES = 100  # Mindest-Samples pro (continent, source)

    sample_counts = df_plot.groupby(["continent", "source"]).size().unstack(fill_value=0)
    plottable_continents = sample_counts[
        (sample_counts.get("SEQ", 0) >= MIN_SAMPLES) &
        (sample_counts.get("MASS", 0) >= MIN_SAMPLES)
        ].index.tolist()

    df_plot = df_plot[df_plot["continent"].isin(plottable_continents)]
    order = [c for c in order if c in plottable_continents]
    xtick_labels = [f"{c}\n({_fmt_count(ip_counts.get(c, 0))})" for c in order]
    print(f"Plottable continents (>= {MIN_SAMPLES} samples per source): {order}")

    # --- Plot-Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(5.2, 2.4))

    palette = {"SEQ": "#6FB8FF", "MASS": "#FF8080"}

    # --- Violin-Plot ---
    sns.violinplot(
        data=df_plot,
        x="continent",
        y="rtt_ms",
        hue="source",
        order=order,
        hue_order=["SEQ", "MASS"],
        split=True,
        inner="quartile",
        density_norm="width",
        width=0.95,
        linewidth=0.5,
        cut=0,
        palette=palette,
        ax=ax,
    )

    # Violin-Bodies: Rand = Füllfarbe (optisch "kein Rand")
    for coll in ax.collections:
        if isinstance(coll, PolyCollection):
            coll.set_edgecolor(coll.get_facecolor())
            coll.set_linewidth(0.3)

    # Quartil-Linien stylen:
    #   Index 0 -> Q25  (außen, dotted)
    #   Index 1 -> Median (mitte, dashed)
    #   Index 2 -> Q75  (außen, dotted)
    for i, line in enumerate(ax.lines):
        if i % 3 == 1:
            line.set_linestyle("--")  # Median: dashed
            line.set_linewidth(0.4)
        else:
            line.set_linestyle(":")  # Q25/Q75: dotted
            line.set_linewidth(0.4)
        line.set_color("gray")

    # --- Achsen ---
    ax.set_xlabel("Continent (#IP Addr.)", labelpad=4)
    ax.set_ylabel("Probing Interval [ms]", labelpad=4)
    ax.set_ylim(bottom=0)

    ax.set_xticks(range(len(order)))
    ax.set_xticklabels(xtick_labels, rotation=0, ha="center")

    # Major ticks alle 100ms, Minor alle 50ms
    ax.yaxis.set_major_locator(MultipleLocator(100))
    ax.yaxis.set_minor_locator(MultipleLocator(50))
    ax.tick_params(axis="y", which="major", length=3, width=0.5)
    ax.tick_params(axis="y", which="minor", length=1.5, width=0.5)
    ax.tick_params(axis="x", which="major", length=3, width=0.5)

    ax.grid(True, axis="y", which="major", linestyle="--", linewidth=0.4, alpha=0.5)
    ax.grid(True, axis="y", which="minor", linestyle=":", linewidth=0.3, alpha=0.3)

    for spine in ax.spines.values():
        spine.set_linewidth(0.5)
        spine.set_color("black")

    # --- Legende in Plot, oben links, mit Remapping ---
    label_map = {"SEQ": "RT-based", "MASS": "Fixed-Interval"}
    handles, orig_labels = ax.get_legend_handles_labels()
    new_labels = [label_map.get(l, l) for l in orig_labels]

    ax.legend(
        handles, new_labels,
        loc="upper left",
        bbox_to_anchor=(0.01, 0.98),
        bbox_transform=ax.transAxes,
        ncol=1,
        frameon=True,
        handlelength=1.2,
        handletextpad=0.3,
        borderpad=0.3,
        labelspacing=0.3,
    )

    plt.tight_layout(pad=0.4)
    plt.savefig(plot_fp, format="pdf", bbox_inches="tight", dpi=300, pad_inches=0.02)
    plt.close(fig)

    print(f"[+] ACM-style RTT violin plot saved to {plot_fp}")

    # --- Info-Datei (auf Basis des vollständigen Datensatzes) ---
    _write_rtt_region_info(info_fp, df, order, msm_path_seq, msm_path_mass,
                           max_samples_per_group=max_samples_per_group)


def _extract_rtts_with_continent(msm_path: str, label: str) -> pd.DataFrame:
    """
    Streamt probing.csv.zst via DuckDB, berechnet Inter-Send-Differenzen
    direkt in SQL und ergänzt Continent per MaxMind-Lookup.

    Rückgabe: DataFrame mit Spalten [ip, rtt_ms, continent, source].
    """
    import maxminddb

    probing_fp = os.path.join(msm_path, "probing.csv.zst")

    con = duckdb.connect(database=":memory:")
    con.execute("PRAGMA threads=16;")
    con.execute("PRAGMA memory_limit='80GB';")

    print(f"  [{label}] Parsing sequences in DuckDB...")

    # Inter-Send-Differenzen komplett in SQL:
    # 1. raw: IP + string -> array<varchar> via string_split
    # 2. exploded: eine Row pro Timestamp, mit row_id (Sequenz-ID) und pos (Position)
    # 3. diffs: Differenz zum vorherigen Timestamp innerhalb derselben Sequenz
    query = f"""
        WITH raw AS (
            SELECT
                IP,
                string_split(SENT_TS_SEQUENCE, ',') AS ts_arr
            FROM read_csv_auto('{probing_fp}', compression='zstd')
            WHERE SENT_TS_SEQUENCE IS NOT NULL
              AND length(SENT_TS_SEQUENCE) > 0
        ),
        exploded AS (
            SELECT
                IP,
                row_number() OVER () AS row_id,
                generate_subscripts(ts_arr, 1) AS pos,
                CAST(unnest(ts_arr) AS BIGINT)  AS ts_us
            FROM raw
        ),
        diffs AS (
            SELECT
                IP,
                (ts_us - lag(ts_us) OVER (PARTITION BY row_id ORDER BY pos)) / 1000.0 AS rtt_ms
            FROM exploded
        )
        SELECT IP AS ip, rtt_ms
        FROM diffs
        WHERE rtt_ms IS NOT NULL AND rtt_ms > 0
    """

    # fetch_arrow_table ist zero-copy und deutlich speicherschonender als fetch_df
    arrow_tbl = con.execute(query).fetch_arrow_table()
    con.close()

    df = arrow_tbl.to_pandas()
    print(f"  [{label}] {len(df):,} RTT samples, "
          f"{df['ip'].nunique():,} unique IPs")

    # --- Continent per MaxMind (mmap, direktes dict-Lookup) ---
    print(f"  [{label}] Resolving GeoIP continents...")
    unique_ips = df["ip"].unique()
    continent_map: dict[str, str] = {}

    with maxminddb.open_database(GEOLITE_COUNTRY_DB,
                                 mode=maxminddb.MODE_MMAP) as reader:
        for ip in unique_ips:
            try:
                result = reader.get(ip)
            except (ValueError, TypeError):
                result = None
            if result and "continent" in result:
                continent_map[ip] = result["continent"]["names"].get("en", "None")
            else:
                continent_map[ip] = "None"

    df["continent"] = df["ip"].map(continent_map)
    df["source"] = label

    # Kategorische Typen sparen massiv RAM bei vielen Duplikaten
    df["continent"] = df["continent"].astype("category")
    df["source"] = df["source"].astype("category")

    return df


def _write_rtt_region_info(
        info_path: str,
        df: pd.DataFrame,
        order: list[str],
        msm_path_seq: str,
        msm_path_mass: str,
        max_samples_per_group: int,
):
    """Schreibt Metadata-Info-Datei für RTT-per-Region-Plot."""
    with open(info_path, "w", encoding="utf-8") as f:
        f.write("RTT per Region Metadata\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Sequential measurement: {msm_path_seq}\n")
        f.write(f"Mass measurement:       {msm_path_mass}\n")
        f.write(f"Downsample cap per (continent, source): "
                f"{max_samples_per_group:,} (plot only)\n\n")

        for src in ["SEQ", "MASS"]:
            sub = df[df["source"] == src]
            f.write(f"--- {src} ---\n")
            f.write(f"Total RTT samples: {len(sub):,}\n")
            f.write(f"Unique IPs:        {sub['ip'].nunique():,}\n")
            if len(sub):
                f.write(f"Overall mean RTT:  {sub['rtt_ms'].mean():.2f} ms\n")
                f.write(f"Overall median:    {sub['rtt_ms'].median():.2f} ms\n")
            f.write("\n")

        f.write("Per-Continent Statistics (full dataset)\n")
        f.write("-" * 60 + "\n")
        f.write(f"{'Continent':<15} {'Source':<6} "
                f"{'#IPs':>10} {'#RTTs':>14} "
                f"{'Mean':>8} {'Median':>8} {'p95':>8}\n")

        for cont in order:
            for src in ["SEQ", "MASS"]:
                sub = df[(df["continent"] == cont) & (df["source"] == src)]
                if sub.empty:
                    continue
                f.write(
                    f"{cont:<15} {src:<6} "
                    f"{sub['ip'].nunique():>10,} "
                    f"{len(sub):>14,} "
                    f"{sub['rtt_ms'].mean():>8.2f} "
                    f"{sub['rtt_ms'].median():>8.2f} "
                    f"{sub['rtt_ms'].quantile(0.95):>8.2f}\n"
                )
            f.write("\n")

    print(f"[+] Info file written to {info_path}")


def sample_targets(input_file: str):
    output_file = os.path.join(
        os.path.dirname(os.path.dirname(input_file)),
        "sample",
        "targets.csv.zst"
    )

    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)

    con = duckdb.connect()

    start_total = time.time()
    print(f"[INFO] Start processing: {input_file}")

    # 1. COUNT
    print("[INFO] Counting total rows...")
    t0 = time.time()
    total_rows = con.execute(f"""
        SELECT COUNT(*) FROM read_csv_auto('{input_file}')
    """).fetchone()[0]
    t1 = time.time()
    print(f"[INFO] Total rows: {total_rows:,} (took {t1 - t0:.2f}s)")

    # 2. Zielgröße
    target_n = max(1_800_000, int(math.ceil(0.09 * total_rows)))
    print(f"[INFO] Target sample size: {target_n:,} rows")

    # 3. Sampling + Export
    print("[INFO] Sampling and writing output...")
    t2 = time.time()
    con.execute(f"""
        COPY (
            SELECT *
            FROM read_csv_auto('{input_file}')
            USING SAMPLE {target_n} ROWS
        )
        TO '{output_file}'
        (FORMAT CSV, COMPRESSION ZSTD);
    """)
    t3 = time.time()

    print(f"[INFO] Sampling + export done (took {t3 - t2:.2f}s)")
    print(f"[INFO] Output written to: {output_file}")
    print(f"[INFO] Total runtime: {time.time() - start_total:.2f}s")

    con.close()


def run_cdf(
        sequence_length: int,
        sequence_count_per_pattern: int,
        force_create_dataset: bool,
        reclassify_dataset: bool,
        close_range: bool,
        test: str = "chi2",
):
    """
    Erzeugt CDF-Plot der p-Values pro Klasse.

    :param force_create_dataset: Wenn True, werden die Sequenzen neu generiert
                                 UND neu klassifiziert.
    :param reclassify_dataset:   Wenn True, werden die Sequenzen aus dem Cache
                                 geladen, aber neu klassifiziert. Ignoriert,
                                 wenn force_create_dataset=True.
    :param close_range:
    :param sequence_length:
    :param sequence_count_per_pattern:
    :param test: "chi2" oder "nist" – wählt den Statistik-Test aus.
    """
    # --- Test-Funktion auswählen ---
    if test == "chi2":
        test_func = chi2_test
        test_label_short = "chi2"
        test_label_math = r"Chi$^2$"
    elif test == "nist":
        test_func = nist_test
        test_label_short = "nist"
        test_label_math = "NIST"
    else:
        raise ValueError(f"Unknown test: {test!r} (expected 'chi2' or 'nist')")

    # --- Pfade ---
    base_name = f"{test_label_short}_cdf_{sequence_length}_{sequence_count_per_pattern}"
    range_suffix = "close" if close_range else "default"

    # Sequenzen-Cache ist test-unabhängig (nur von seq_length + count)
    sequences_fp = os.path.join(
        TEST_RESULTS,
        f"sequences_{sequence_length}_{sequence_count_per_pattern}.pkl",
    )
    # p-Value Cache ist test-spezifisch
    pvalues_fp = os.path.join(TEST_RESULTS, f"{base_name}.pkl")
    plot_fp    = os.path.join(TEST_RESULTS, f"{base_name}_{range_suffix}.pdf")
    info_fp    = os.path.join(TEST_RESULTS, f"{base_name}_info.txt")

    # --- Entscheidung: was muss neu gemacht werden? ---
    need_regenerate_sequences = force_create_dataset or not os.path.exists(sequences_fp)
    need_reclassify = force_create_dataset or reclassify_dataset or not os.path.exists(pvalues_fp)

    # --- Sequenzen laden oder generieren ---
    if need_regenerate_sequences:
        print(f"Generating sequences (length={sequence_length}, count={sequence_count_per_pattern} per pattern)...")
        sequences_per_class: dict[str, list] = {}
        for pattern, generator in pattern_generation_map.items():
            if generator is None:
                continue
            seqs = [generator(sequence_length) for _ in range(sequence_count_per_pattern)]
            sequences_per_class[pattern.value] = seqs
            print(f"  {pattern.value}: {len(seqs)} sequences")

        with open(sequences_fp, "wb") as f:
            pickle.dump(sequences_per_class, f)
        print(f"Cached sequences to {sequences_fp}")
    else:
        print(f"Loading cached sequences from {sequences_fp}")
        with open(sequences_fp, "rb") as f:
            sequences_per_class = pickle.load(f)

    # --- Klassifikation: p-Values berechnen oder aus Cache ---
    if need_reclassify:
        print(f"Computing {test_label_short} p-values...")
        pvalues_per_class: dict[str, list[float]] = {}
        for cls, seqs in sequences_per_class.items():
            pvalues = []
            for seq in seqs:
                s  = test_func(seq.s.increments)
                a  = test_func(seq.a.increments)
                b  = test_func(seq.b.increments)
                ap = test_func(seq.ap.increments)
                bp = test_func(seq.bp.increments)
                pvalues.append(min(s, a, b, ap, bp))

            pvalues_per_class[cls] = pvalues
            print(f"  {cls}: {len(pvalues)} samples, "
                  f"min={min(pvalues):.2e}, max={max(pvalues):.2e}")

        with open(pvalues_fp, "wb") as f:
            pickle.dump(pvalues_per_class, f)
        print(f"Cached p-values to {pvalues_fp}")
    else:
        print(f"Loading cached {test_label_short} p-values from {pvalues_fp}")
        with open(pvalues_fp, "rb") as f:
            pvalues_per_class = pickle.load(f)

    # --- Plot + Info ---
    _plot_cdf(pvalues_per_class, plot_fp, close_range, test_label_math)
    _write_cdf_info(
        info_fp, pvalues_per_class,
        sequence_length, sequence_count_per_pattern,
        test_label_short, test_label_math,
    )


def _plot_cdf(
        pvalues_per_class: dict[str, list[float]],
        out_path: str,
        close_range: bool,
        test_label_math: str,
):
    """CDF der p-Values pro Klasse (Test-agnostisch)."""
    display_map = {
        "Mirror": ("Reflection", "#FFE866"),
        "Constant": ("Constant", "#6FB8FF"),
        "Single": ("Single", "#FF8080"),
        "Per-Dst": ("Per-Destination", "#B580FF"),
        "Per-Con": ("Per-Connection", "#FF85C1"),
        "Per-Bucket": ("Per-Bucket", "#6EE66E"),
        "Per-CPU": ("Multi", "#66E0E0"),
        "Random": ("Random", "#FFB266"),
        "Fallback": ("Unclassified", "#CCCCCC"),
    }
    order_index = {k: i for i, k in enumerate(display_map)}

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman", "Times New Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(4.5, 3.0))

    ordered_classes = sorted(
        pvalues_per_class.keys(),
        key=lambda c: order_index.get(c, 999),
    )

    # --- Trenne 0-Werte von positiven, bestimme Skalen-Range ---
    positive_values = [
        p for pvs in pvalues_per_class.values() for p in pvs if p > 0
    ]
    has_zeros = any(
        p <= 0 for pvs in pvalues_per_class.values() for p in pvs
    )

    min_positive = min(positive_values, default=1e-300)

    # Reservierte x-Position für echte Nullen, eine Dekade links
    # der kleinsten positiven Beobachtung.
    zero_slot_x = min_positive / 10.0

    # --- Plotte CDFs ---
    for cls in ordered_classes:
        pvs = np.asarray(pvalues_per_class[cls], dtype=float)

        # Echte Nullen bekommen die reservierte Slot-Position,
        # alle anderen Werte bleiben unverändert.
        pvs_plot = np.where(pvs <= 0, zero_slot_x, pvs)

        pvs_sorted = np.sort(pvs_plot)
        cdf = np.arange(1, len(pvs_sorted) + 1) / len(pvs_sorted) * 100

        display_name, color = display_map.get(cls, (cls, "#808080"))
        ax.plot(
            pvs_sorted, cdf,
            label=display_name,
            color=color,
            linewidth=1.4,
        )

    # --- X-Achse ---
    ax.set_xscale("log")

    if close_range:
        ax.set_xlim(left=1e-5, right=1.0)
    else:
        min_exp = int(np.floor(np.log10(min_positive)))
        max_exp = 0
        step = 20
        start_exp = (min_exp // step) * step
        exponents = np.arange(start_exp, max_exp + 1, step)
        if exponents[-1] != 0:
            exponents = np.append(exponents, 0)

        major_ticks = 10.0 ** exponents
        major_labels = [rf"$10^{{{e}}}$" for e in exponents]

        # Nur wenn echte Nullen vorhanden sind: "0"-Slot ergänzen
        if has_zeros and test_label_math == "NIST":
            major_ticks = np.concatenate(([zero_slot_x], major_ticks))
            major_labels = ["0"] + major_labels
            left_lim = zero_slot_x / 3.0  # etwas Platz links vom 0-Tick

            # Visuelle Trennung zwischen "0"-Slot und Rest der Achse
            sep_x = zero_slot_x * np.sqrt(10)  # geometrisches Mittel
            ax.axvline(sep_x, color="black", linewidth=0.4,
                       linestyle=(0, (2, 2)), alpha=0.6)
        else:
            left_lim = major_ticks[0]

        ax.set_xticks(major_ticks)
        ax.set_xticklabels(major_labels)

        # Minor-Ticks zwischen den Major-Ticks (nur im positiven Bereich)
        minor_exponents = exponents[:-1] + step / 2
        minor_ticks = 10.0 ** minor_exponents
        ax.set_xticks(minor_ticks, minor=True)
        ax.xaxis.set_minor_formatter(NullFormatter())

        ax.set_xlim(left=left_lim, right=1.0)

    # --- Y-Achse ---
    y_major = np.arange(0, 101, 20)
    ax.set_yticks(y_major)
    y_minor = y_major[:-1] + 10
    ax.set_yticks(y_minor, minor=True)
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_ylim(0, 105)

    # --- Labels & Styling ---
    ax.set_xlabel(
        rf"{test_label_math} p-value [Minimum of all Subsequences]",
        labelpad=2,
    )
    ax.set_ylabel("Cumulative Percentage [%]", labelpad=2)

    ax.grid(True, which="major", linestyle="--", linewidth=0.4, alpha=0.5)
    ax.grid(True, which="minor", linestyle=":", linewidth=0.3, alpha=0.3)

    for spine in ax.spines.values():
        spine.set_linewidth(0.5)

    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        bbox_transform=ax.transAxes,
        ncol=4,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    plt.tight_layout(pad=0.4)
    plt.savefig(out_path, bbox_inches="tight", dpi=300, pad_inches=0.05)
    plt.close(fig)
    print(f"[+] {test_label_math} CDF plot saved to {out_path}")


def _write_cdf_info(
        info_path: str,
        pvalues_per_class: dict[str, list[float]],
        sequence_length: int,
        sequence_count_per_pattern: int,
        test_label_short: str,
        test_label_math: str,
):
    """Schreibt Metadata-Info-Datei für CDF-Plot (Test-agnostisch)."""
    display_map = {
        "Mirror": "Reflection",
        "Constant": "Constant",
        "Single": "Single",
        "Per-Dst": "Per-Destination",
        "Per-Con": "Per-Connection",
        "Per-Bucket": "Per-Bucket",
        "Per-CPU": "Multi",
        "Random": "Random",
        "Fallback": "Unclassified",
    }
    order_index = {k: i for i, k in enumerate(display_map)}

    thresholds = [1e-60, 1e-30, 1e-12, 1e-6, 1e-3, 0.01, 0.05]

    with open(info_path, "w", encoding="utf-8") as f:
        f.write(f"{test_label_math} CDF Metadata\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Test:                       {test_label_short}\n")
        f.write(f"Sequence length:            {sequence_length}\n")
        f.write(f"Sequences per pattern:      {sequence_count_per_pattern:,}\n")
        f.write(f"p-value = Min({test_label_short}-p over all 5 subsequences s, a, b, ap, bp)\n\n")

        f.write("Per-Class Statistics\n")
        f.write("-" * 60 + "\n")

        ordered = sorted(
            pvalues_per_class.keys(),
            key=lambda c: order_index.get(c, 999),
        )

        for cls in ordered:
            pvs = np.asarray(pvalues_per_class[cls], dtype=float)
            display_name = display_map.get(cls, cls)

            n = len(pvs)
            n_zero = int(np.sum(pvs <= 0))
            pvs_pos = pvs[pvs > 0]

            f.write(f"\n{display_name} ({cls}):\n")
            f.write(f"  Samples:            {n:,}\n")
            f.write(f"  Exact zeros:        {n_zero:,} ({n_zero / n * 100:.2f}%)\n")
            if pvs_pos.size:
                f.write(f"  Min (non-zero):     {pvs_pos.min():.3e}\n")
                f.write(f"  Max:                {pvs.max():.3e}\n")
                f.write(f"  Median:             {np.median(pvs):.3e}\n")
                f.write(f"  Mean:               {pvs.mean():.3e}\n")

            f.write(f"  Fraction below threshold:\n")
            for th in thresholds:
                pct = np.sum(pvs <= th) / n * 100
                f.write(f"    p <= {th:>9.0e}:  {pct:6.2f}%\n")

    print(f"[+] Info file written to {info_path}")


def classify_first_four_for_per_con(msm_path):
    probing_path = os.path.join(msm_path, "probing.csv.zst")

    def classifier(arr) -> str | None:
        ip_id_seq = IPIDSequence(arr)
        pattern = get_pattern(seq=ip_id_seq, is_mass_scan=False, get_all=False)
        if pattern != Pattern.PER_CON:
            return None

        non_con_ip_id_seq = IPIDSequence(arr[:4])
        non_con_pattern = get_pattern(seq=non_con_ip_id_seq, is_mass_scan=False, get_all=False)
        return non_con_pattern.value

    ranking = defaultdict(int)
    total_classified = 0

    local_classifier = classifier
    ranking_local = ranking

    # --- decompress to tempfile ---
    tmp_path = os.path.join(msm_path, "probing_decompressed.csv")

    with open(probing_path, "rb") as f:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(f) as reader:
            with open(tmp_path, "wb") as tmp:
                shutil.copyfileobj(reader, tmp)

    try:
        # --- single connection ---
        con = duckdb.connect(database=":memory:")
        con.execute("PRAGMA threads=8")

        cursor = con.execute("""
            SELECT IP_ID_SEQUENCE
            FROM read_csv_auto(?, delim=',', header=True)
            WHERE IP_ID_SEQUENCE IS NOT NULL
        """, [tmp_path])

        while True:
            chunk = cursor.fetchmany(500_000)
            if not chunk:
                break

            for row in chunk:
                seq_str = row[0]

                try:
                    seq = np.fromstring(seq_str, dtype=np.int32, sep=",")
                    if seq.size < 4:
                        continue
                except Exception:
                    continue

                cls = local_classifier(seq)
                if cls is None:
                    continue

                ranking_local[cls] += 1
                total_classified += 1

    finally:
        os.remove(tmp_path)

    if total_classified == 0:
        print("No classified samples.")
        return

    print("Relative class distribution:")

    sorted_items = sorted(
        ranking.items(),
        key=lambda x: x[1] / total_classified,
        reverse=True
    )

    for cls, count in sorted_items:
        rel = count / total_classified
        print(f"{cls}: {rel:.4f} ({count})")


def merge_eval_with_rst(msm_path, rst_path, class_filter):
    con = duckdb.connect()

    eval_path = os.path.join(msm_path, "eval_std.csv.zst")
    probing_path = os.path.join(msm_path, "probing_std.csv.zst")
    output_eval_path = os.path.join(msm_path, "eval.csv.zst")
    output_probing_path = os.path.join(msm_path, "probing.csv.zst")

    # --- Count total eval rows ---
    total_count = con.execute(f"""
        SELECT COUNT(*) 
        FROM read_csv_auto('{eval_path}', compression='zstd')
    """).fetchone()[0]

    # --- Count matches ---
    match_count = con.execute(f"""
        SELECT COUNT(*) 
        FROM read_csv_auto('{eval_path}', compression='zstd') e
        INNER JOIN (
            SELECT DISTINCT saddr
            FROM read_csv_auto('{rst_path}', compression='zstd')
            WHERE classification = '{class_filter}'
        ) r
        ON e.IP = r.saddr
    """).fetchone()[0]

    # --- Create filtered eval with stable ordering ---
    con.execute(f"""
        CREATE TEMP TABLE eval_filtered AS
        SELECT 
            e.*,
            row_number() OVER () AS rn
        FROM read_csv_auto('{eval_path}', compression='zstd') e
        INNER JOIN (
            SELECT DISTINCT saddr
            FROM read_csv_auto('{rst_path}', compression='zstd')
            WHERE classification = '{class_filter}'
        ) r
        ON e.IP = r.saddr;
    """)

    # --- Write eval output ---
    con.execute(f"""
        COPY (
            SELECT * EXCLUDE (rn)
            FROM eval_filtered
            ORDER BY rn
        )
        TO '{output_eval_path}'
        (FORMAT CSV, HEADER TRUE, COMPRESSION ZSTD);
    """)

    # --- Align probing EXACTLY to eval_filtered (same order, same multiplicity) ---
    con.execute(f"""
        COPY (
            SELECT p.*
            FROM eval_filtered e
            JOIN read_csv_auto('{probing_path}', compression='zstd') p
            ON e.IP = p.IP
            ORDER BY e.rn
        )
        TO '{output_probing_path}'
        (FORMAT CSV, HEADER TRUE, COMPRESSION ZSTD);
    """)

    con.close()

    # --- Ratio ---
    ratio = match_count / total_count if total_count > 0 else 0.0
    print(f"Matches: {match_count} / {total_count} ({ratio:.4f})")

    return ratio


def filter_probing_by_targets(msm_path):
    probing_file = os.path.join(msm_path, "probing_old.csv.zst")
    targets_file = os.path.join(msm_path, "targets.csv.zst")
    output_file = os.path.join(msm_path, "probing.csv.zst")

    con = duckdb.connect()

    query = f"""
    COPY (
        SELECT p.*
        FROM read_csv_auto('{probing_file}', compression='zstd') p
        SEMI JOIN read_csv_auto('{targets_file}', compression='zstd') t
        ON p.IP = t.IP
    )
    TO '{output_file}' (HEADER, COMPRESSION 'zstd');
    """

    con.execute(query)
    con.close()


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


def plot_caida_os_distribution_acm_style(
        caida_itdk_path: str,
        msm_path: str,
        show_dst_only: bool = True,
        bar_height: float = 0.2,
        bar_gap: float = 0.2,
        y_padding: float = 0.1,
):
    # --- Pfade ---
    ip_to_node_file = os.path.join(caida_itdk_path, "ip_to_node.csv.zst")
    targets_base_path = os.path.dirname(os.readlink(os.path.join(msm_path, "targets.csv.zst")))
    targets_os_file = os.path.join(targets_base_path, "targets_os.csv.zst")
    out_dir = os.path.join(msm_path, "analysis", "caida_os_distribution")
    os.makedirs(out_dir, exist_ok=True)

    # --- Daten laden via DuckDB ---
    con = duckdb.connect(database=":memory:")
    con.execute(f"""
        CREATE VIEW ip_to_node AS
        SELECT IP, T, D FROM read_csv_auto('{ip_to_node_file}', compression='zstd');
    """)
    con.execute(f"""
        CREATE VIEW targets_os AS
        SELECT IP, OS FROM read_csv_auto('{targets_os_file}', compression='zstd');
    """)
    df_joined = con.execute("""
        SELECT n.IP, n.T, n.D, t.OS
        FROM ip_to_node n
        LEFT JOIN targets_os t ON n.IP = t.IP
        WHERE (n.T = 1) OR (n.T = 0 AND n.D = 1)
    """).fetch_df()
    con.close()

    df_joined = df_joined[df_joined["OS"].notna()]
    df_joined["OS"] = df_joined["OS"].astype(str).str.lower()

    # --- OS -> Gruppe/Raw mapping ---
    def map_os_to_group_or_raw(os_str):
        for group, (members, _) in os_groups.items():
            if os_str in members:
                return group
        return os_str

    df_joined["LABEL"] = df_joined["OS"].apply(map_os_to_group_or_raw)

    # Save CSV
    df_joined.to_csv(os.path.join(out_dir, "caida_os.csv.zst"),
                     index=False, compression="zstd")

    # --- Distributions ---
    transit = df_joined[df_joined["T"] == 1]
    endhost = df_joined[(df_joined["T"] == 0) & (df_joined["D"] == 1)]

    transit_dist = transit["LABEL"].value_counts(normalize=True) * 100
    endhost_dist = endhost["LABEL"].value_counts(normalize=True) * 100

    # --- Display-Map bauen (Reihenfolge = Sortier- und Legendenreihenfolge) ---
    # Basis: OS-Gruppen in definierter Reihenfolge
    display_map = {
        grp: (grp, col) for grp, (_, col) in os_groups.items()
    }

    # Zusätzliche einzelne OSes > 1% in stabiler Reihenfolge anhängen
    extra_labels = sorted(
        lbl for lbl in set(df_joined["LABEL"])
        if lbl not in os_groups
        and (transit_dist.get(lbl, 0) > 1 or endhost_dist.get(lbl, 0) > 1)
    )

    def _stable_color(name: str) -> str:
        h = hashlib.sha1(name.encode("utf-8")).hexdigest()
        return soft_palette[int(h[:8], 16) % len(soft_palette)]

    for lbl in extra_labels:
        display_map[lbl] = (pretty_oses.get(lbl, lbl), _stable_color(lbl))

    # Fallback/Unclassified vor "Other"
    if "Fallback" in display_map:
        display_map["Fallback"] = ("Unclassified", display_map["Fallback"][1])

    # "Other" als letzte Kategorie
    display_map["Other"] = ("Other", fallback_color)

    # --- Gefilterte Klassen (>1% in mindestens einem Datensatz) + Other ---
    all_classes = [
        cls for cls in display_map
        if cls != "Other" and (
                transit_dist.get(cls, 0) > 1 or endhost_dist.get(cls, 0) > 1
        )
    ]

    transit_values = [transit_dist.get(c, 0.0) for c in all_classes]
    endhost_values = [endhost_dist.get(c, 0.0) for c in all_classes]

    # Rest zu 100% als "Other"
    all_classes.append("Other")
    transit_values.append(100 - sum(transit_values))
    endhost_values.append(100 - sum(endhost_values))

    # --- Plot-Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    # --- Geometrie ---
    data_sets = []
    labels = []

    if show_dst_only:
        data_sets.append(endhost_values)
        labels.append("All Others")

    data_sets.append(transit_values)
    labels.append("Router")

    n_bars = len(data_sets)

    total_height = 2 * y_padding + n_bars * bar_height + max(n_bars - 1, 0) * bar_gap
    y_positions = [
        y_padding + bar_height / 2 + i * (bar_height + bar_gap)
        for i in range(n_bars)
    ]

    fig_width = 5.0
    fig, ax = plt.subplots(figsize=(fig_width, total_height))

    bars = []
    for y, values in zip(y_positions, data_sets):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = display_map.get(cls, ("?", "#CCCCCC"))[1]
            bar = ax.barh(
                y, val, left=left, height=bar_height,
                edgecolor="none", color=color
            )
            current_bars.append(bar)

            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",
                    ha="center", va="center",
                    fontsize=9, color="black"
                )
            left += val
        bars = current_bars

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(0, total_height)

    ax.set_xlabel("OS Distribution [%]")
    ax.set_ylabel("Device Type", rotation=90, labelpad=6)

    ax.xaxis.set_minor_locator(MultipleLocator(5))
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    # --- Legende ---
    legend_labels = [display_map.get(c, (c, None))[0] for c in all_classes]
    ncol = int(math.ceil(len(legend_labels) / 2))
    ax.legend(
        [b[0] for b in bars],
        legend_labels,
        loc="lower center",
        bbox_to_anchor=(0.42, 1.0) if show_dst_only else (0.44, 1.4),
        bbox_transform=ax.transAxes,
        ncol=ncol,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    out_file = os.path.join(out_dir, "os_distribution_acm_style_new.pdf")
    plt.savefig(out_file, format="pdf", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    print(f"[+] CAIDA OS distribution saved to {out_file}")

    # --- Metadata export ---
    _write_caida_os_info(
        os.path.join(out_dir, "info.txt"),
        transit, endhost,
        transit_dist, endhost_dist,
        all_classes,
        transit_other=transit_values[-1],
        endhost_other=endhost_values[-1],
    )


def _write_caida_os_info(info_path, transit, endhost,
                         transit_dist, endhost_dist,
                         ordered_labels,
                         transit_other, endhost_other):
    """Schreibt Metadata-Info-Datei für die CAIDA OS Distribution."""
    transit_abs = transit["LABEL"].value_counts()
    endhost_abs = endhost["LABEL"].value_counts()

    with open(info_path, "w") as f:
        f.write("CAIDA OS Distribution Metadata\n")
        f.write("=====================================\n\n")
        f.write(f"Total Transit-hops: {len(transit)}\n")
        f.write(f"Total End-hosts:    {len(endhost)}\n\n")
        f.write("Per-OS Statistics (absolute and percentage)\n")
        f.write("--------------------------------------------------\n")

        for lbl in ordered_labels:
            if lbl == "Other":
                pct_t = transit_other
                pct_e = endhost_other
                abs_t = ""  # kein sauberer Absolutwert für "Other"
                abs_e = ""
            else:
                pct_t = transit_dist.get(lbl, 0)
                pct_e = endhost_dist.get(lbl, 0)
                abs_t = transit_abs.get(lbl, 0)
                abs_e = endhost_abs.get(lbl, 0)

            f.write(
                f"{lbl}:\n"
                f"  Transit:  {abs_t}  ({pct_t:.2f}%)\n"
                f"  End-host: {abs_e}  ({pct_e:.2f}%)\n\n"
            )


def plot_random_ipid_sequence(msm_path: str, pattern_name: str, count: int = 10):
    probing_path = os.path.join(msm_path, "probing.csv.zst")
    eval_path = os.path.join(msm_path, "eval.csv.zst")

    con = duckdb.connect()

    rows = con.execute(f"""
        WITH eval AS (
            SELECT IP
            FROM read_csv_auto('{eval_path}', compression='zstd')
            WHERE TRIM(IP_ID_PATTERN) = '{pattern_name}'
            ORDER BY RANDOM()
            LIMIT {count}
        )
        SELECT e.IP, p.IP_ID_SEQUENCE
        FROM eval e
        JOIN read_csv_auto('{probing_path}', compression='zstd') p
        ON e.IP = p.IP
    """).fetchall()

    if not rows:
        print(f"No entries found for pattern '{pattern_name}'")
        return

    for ip, seq in rows:
        if not seq:
            print(f"No IPID sequence found for IP {ip}")
            continue

        y = list(map(int, seq.split(',')))

        plt.figure()
        plt.plot(range(1, len(y) + 1), y, marker="o")
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
    print(f"Plotting ACM-style OS Heatmap for {ident}")

    # --- Pfade ---
    eval_path = os.path.join(msm_path, "eval.csv.zst")
    targets_base_path = os.path.dirname(os.readlink(os.path.join(msm_path, "targets.csv.zst")))
    targets_os_path = os.path.join(targets_base_path, "targets_os.csv.zst")
    analysis_dir = os.path.join(msm_path, "analysis", "os_heatmap", ident)

    # --- Klassen-Mapping (Reihenfolge = Spaltenreihenfolge in der Heatmap) ---
    # raw_name -> display_name
    display_map = {
        "Mirror": "Reflection",
        "Constant": "Constant",
        "Single": "Single",
        "Per-Con": "Per-Connection",
        "Per-Dst": "Per-Destination",
        "Per-Bucket": "Per-Bucket",
        "Per-CPU": "Multi",
        "Random": "Random",
        "Fallback": "Unclassified",
    }

    # --- Daten laden ---
    con = duckdb.connect(database=":memory:")
    con.execute("PRAGMA threads=8;")

    os_case_parts = [
        f"WHEN lower(t.OS) = '{name.lower()}' THEN '{label}'"
        for os_list, label in os_groups
        for name in os_list
    ]
    os_case = " ".join(os_case_parts)

    query = f"""
        SELECT e.IP_ID_PATTERN AS class,
               CASE {os_case} ELSE 'Other' END AS os_group
        FROM read_csv_auto('{eval_path}') AS e
        JOIN read_csv_auto('{targets_os_path}') AS t
        ON e.IP = t.IP
    """
    df = con.execute(query).fetch_df()
    con.close()

    # --- Pivot-Table bauen ---
    pivot = df.value_counts().reset_index()
    pivot.columns = ["class", "os_group", "count"]
    pivot_table = pivot.pivot(index="os_group", columns="class", values="count").fillna(0)

    # Klassen-Spalten umbenennen (nur die, die existieren)
    pivot_table = pivot_table.rename(columns=display_map)

    # --- Reihenfolge OS-Gruppen (Zeilen) gemäß os_groups, "Other" ans Ende ---
    row_order = [label for _, label in os_groups if label in pivot_table.index]
    # if "Other" in pivot_table.index:
    #     row_order.append("Other")
    pivot_table = pivot_table.loc[row_order]

    # --- Reihenfolge Klassen (Spalten) gemäß display_map ---
    col_order = [display_map[k] for k in display_map if display_map[k] in pivot_table.columns]
    pivot_table["Total"] = pivot_table[col_order].sum(axis=1)
    pivot_table = pivot_table[col_order + ["Total"]]

    # --- Relative Werte ---
    pivot_table_rel = (
            pivot_table[col_order].div(pivot_table["Total"], axis=0) * 100
    )

    # --- Plot ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "pdf.fonttype": 42,
    })

    plt.figure(figsize=(5.0, 2.5))
    ax = sns.heatmap(
        pivot_table_rel,
        annot=True,
        fmt=".1f",
        cmap=white_blues,
        vmin=0,
        vmax=100,
        cbar_kws={"label": "Percentage [%]"},
        linewidths=0.4,
        linecolor="white",
    )

    # y-Labels mit Total-Count
    os_labels = [
        f"{os_name} ({_fmt_count(total)})"
        for os_name, total in zip(pivot_table.index, pivot_table["Total"])
    ]
    ax.set_yticklabels(os_labels, rotation=0)

    plt.xlabel("IP-ID Selection Strategy", labelpad=4)
    plt.ylabel("OS Group (#IP Addr.)", labelpad=4)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=30, ha="right")

    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_linewidth(0.5)
        spine.set_color("black")

    plt.tight_layout(pad=0.4)

    # --- Speichern ---
    os.makedirs(analysis_dir, exist_ok=True)
    pivot_table_rel.to_pickle(os.path.join(analysis_dir, "data.pkl"))
    plt.savefig(os.path.join(analysis_dir, "plot_new.pdf"), bbox_inches="tight", dpi=300)

    with open(os.path.join(analysis_dir, "info.txt"), "w", encoding="utf-8") as f:
        f.write("=== Absolute Counts (including Totals) ===\n")
        f.write(pivot_table.to_string(float_format=lambda x: f"{int(x)}"))
        f.write("\n\n=== Relative Percentages ===\n")
        f.write(pivot_table_rel.to_string(float_format=lambda x: f"{x:.1f}%"))

    plt.close()
    print("Done.")


def _fmt_count(n: float) -> str:
    """Kompakte Zahlendarstellung für OS-Labels."""
    if n >= 1_000_000:
        val = f"{n / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{val}M"
    if n >= 10_000:
        return f"{int(n / 1000)}k"
    if n >= 1000:
        val = f"{n / 1000:.1f}".rstrip("0").rstrip(".")
        return f"{val}k"
    return str(int(n))


def plot_os_heatmap_combined(msm_path: str, idents: list[tuple[str, str]], name: str):
    """
    Kombiniert mehrere bereits erzeugte OS-Heatmaps zu einem Plot mit geteilter x-Achse.

    :param msm_path: Basis-Pfad zu den Messungen
    :param idents: Liste von (ident, subplot_title) Paaren.
                   'ident' muss zuvor per plot_os_heatmap() erzeugt worden sein.
    :param name: Dateiname für die kombinierte Ausgabe.
    """
    print(f"Plotting combined OS Heatmap: {name}")

    # --- Daten laden ---
    tables = []
    totals = []
    for ident, _ in idents:
        analysis_dir = os.path.join(msm_path, "analysis", "os_heatmap", ident)
        pkl_path = os.path.join(analysis_dir, "data.pkl")
        info_path = os.path.join(analysis_dir, "info.txt")

        rel = pd.read_pickle(pkl_path)
        tables.append(rel)
        totals.append(_parse_totals_from_info(info_path, rel.index))

    # --- Plot-Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.fontsize": 10,
        "pdf.fonttype": 42,
    })

    # --- Figure ---
    n_subplots = len(tables)
    row_counts = [len(t.index) for t in tables]
    cell_h = 0.15
    fig_height = sum(row_counts) * cell_h + 1.8  # etwas mehr Platz wg. Titeln

    fig, axes = plt.subplots(
        n_subplots, 1,
        figsize=(5.0, fig_height),
        gridspec_kw={"height_ratios": row_counts},
        sharex=True,
    )
    if n_subplots == 1:
        axes = [axes]

    for i, (ax, (ident, subplot_title), rel, totals_i) in enumerate(
            zip(axes, idents, tables, totals)
    ):
        is_last = (i == n_subplots - 1)

        # Annotation-Matrix: "-" für 0, sonst "X.X"
        annot_matrix = rel.map(lambda v: "-" if v == 0 else f"{v:.1f}")

        sns.heatmap(
            rel,
            ax=ax,
            annot=annot_matrix,
            fmt="",
            cmap=white_blues,
            vmin=0, vmax=100,
            linewidths=0.4,
            linecolor="white",
            cbar=False,
        )

        # y-Labels mit Total-Count (nur Tick-Labels, KEIN ylabel pro Subplot)
        os_labels = [
            f"{os_name} ({_fmt_count(totals_i.get(os_name, 0))})"
            for os_name in rel.index
        ]
        ax.set_yticklabels(os_labels, rotation=0)
        ax.set_ylabel("")

        # Subplot-Titel
        ax.set_title(subplot_title, fontsize=10, pad=5)

        # x-Labels nur beim untersten Subplot
        if is_last:
            ax.set_xlabel("IP-ID Selection Strategy", labelpad=4)
            ax.set_xticklabels(ax.get_xticklabels(), rotation=30, ha="right")
        else:
            ax.set_xlabel("")
            ax.tick_params(axis="x", which="both", labelbottom=False)

        for spine in ax.spines.values():
            spine.set_visible(True)
            spine.set_linewidth(0.5)
            spine.set_color("black")

    # --- Layout: mehr Abstand zwischen Subplots ---
    fig.subplots_adjust(left=0.38, right=0.88, top=0.93, bottom=0.18, hspace=0.25)

    # --- Gemeinsames y-Label (zentriert über beide Subplots) ---
    top_ax_bbox = axes[0].get_position()
    bot_ax_bbox = axes[-1].get_position()
    y_center = (top_ax_bbox.y1 + bot_ax_bbox.y0) / 2
    fig.text(
        -0.03, y_center,
        "Operating System (#IP Addr.)",
        rotation=90, va="center", ha="left",
        fontsize=10,
    )

    # --- Gemeinsame Colorbar, vertikal zentriert ---
    top_ax_bbox = axes[0].get_position()
    bot_ax_bbox = axes[-1].get_position()
    y_center = (top_ax_bbox.y1 + bot_ax_bbox.y0) / 2

    cbar_height_inches = 1.5    # feste Länge, anpassbar
    cbar_height_fig = cbar_height_inches / fig.get_figheight()

    cbar_ax = fig.add_axes([
        0.90,
        y_center - cbar_height_fig / 2,
        0.015,
        cbar_height_fig,
        ])

    sm = plt.cm.ScalarMappable(cmap=white_blues, norm=plt.Normalize(vmin=0, vmax=100))
    sm.set_array([])
    cbar = fig.colorbar(sm, cax=cbar_ax, label="Percentage [%]")

    # Ränder der Colorbar an Heatmap-Spines angleichen (linewidth=0.5, schwarz)
    cbar.outline.set_linewidth(0.5)
    cbar.outline.set_edgecolor("black")
    cbar_ax.tick_params(width=0.5)

    # --- Speichern ---
    out_dir = os.path.join(msm_path, "analysis", "os_heatmap_combined")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{name}.pdf")
    plt.savefig(out_path, bbox_inches="tight", dpi=300, pad_inches=0.02)
    plt.close(fig)

    print(f"[+] Combined heatmap saved to {out_path}")


def _parse_totals_from_info(info_path: str, expected_os_groups) -> dict:
    """
    Extrahiert die 'Total'-Spalte aus dem 'Absolute Counts'-Block von info.txt.
    Gibt ein dict {os_group: total_int} zurück.
    """
    totals = {}
    with open(info_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Abschnitt vor "=== Relative" nehmen
    abs_block = content.split("=== Relative")[0]
    lines = abs_block.splitlines()

    # Header-Zeile finden (enthält "Total")
    header_idx = None
    for i, line in enumerate(lines):
        if "Total" in line and not line.startswith("==="):
            header_idx = i
            break
    if header_idx is None:
        return totals

    # Datenzeilen: alles nach dem Header, non-empty, kein "==="
    for line in lines[header_idx + 1:]:
        line = line.rstrip()
        if not line or line.startswith("==="):
            continue
        # Erste Spalte = os_group (kann Leerzeichen enthalten, z.B. "Ubuntu/Debian")
        # Letzte Zahl = Total
        parts = line.split()
        if not parts:
            continue
        try:
            total = int(parts[-1])
        except ValueError:
            continue
        # os_group = alles vor der ersten rein-numerischen Spalte
        os_name_parts = []
        for p in parts:
            try:
                int(p)
                break
            except ValueError:
                os_name_parts.append(p)
        os_name = " ".join(os_name_parts)
        if os_name in expected_os_groups:
            totals[os_name] = total

    return totals


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
    patterns = ["Single", "Per-Dst", "Per-Con", "Per-Bucket", "Random"]
    counts = [19, 6, 7, 9, 2]

    dist = {
        "Single": (4, 14, 7),
        "Per-Bucket": (0, 7, 3),
        "Per-Con": (0, 5, 2),
        "Per-Dst": (0, 3, 4),
        "Random": (1, 1, 2),
    }

    # --- Sortieren nach counts (absteigend) ---
    data = list(zip(patterns, counts))
    data.sort(key=lambda x: x[1], reverse=True)
    patterns, counts = zip(*data)

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    plt.figure(figsize=(5.0, 2.0))
    plt.gca().invert_yaxis()

    left = np.zeros(len(counts))
    colors = ["#E8A2A2", "#9EC9B9", "#9DB7D5"]
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
                    fontsize=9,
                    color="black"
                )

        left += values

    # --- Gesamtzahl rechts ---
    for y, c in enumerate(counts):
        plt.text(c + 0.2, y, f"{c}", va="center", fontsize=9)

    plt.xlabel("Papers [#]")
    plt.ylabel("IP-ID Selection Method")
    plt.legend(frameon=False, ncol=3, loc="lower right", handlelength=1.2, handletextpad=0.3, columnspacing=0.8,
               borderaxespad=0.2)

    ax = plt.gca()

    # Major ticks alle 3
    ax.xaxis.set_major_locator(MultipleLocator(3))

    # Minor ticks alle 1
    ax.xaxis.set_minor_locator(MultipleLocator(1))

    # Tick Länge (optional für schöneres Paper Layout)
    ax.tick_params(axis="x", which="major", length=5, width=0.8)
    ax.tick_params(axis="x", which="minor", length=2.5, width=0.6)

    plt.margins(x=0.15)
    plt.tight_layout()
    plt.savefig(os.path.join(EXPERIMENTAL_RESULTS, "ipid_papers.pdf"), bbox_inches="tight")


def plot_pattern_distribution_acm_style(
        msm_path_1: str,
        msm_path_2: str,
        msm_path_3: str,
        name: str,
        bar_height: float = 0.2,
        bar_gap: float = 0.2,
        y_padding: float = 0.1,
):
    # --- Load data ---
    def _load_data(msm_path):
        data_path = os.path.join(msm_path, "analysis", "pattern_distribution", "data.pkl")
        with open(data_path, "rb") as f:
            data = pickle.load(f)
        if isinstance(data, pd.DataFrame):
            data = dict(zip(data["class"], data["relative"]))
        return data

    data1 = _load_data(msm_path_1)
    data2 = _load_data(msm_path_2)
    data3 = _load_data(msm_path_3)

    # --- Map classes ---
    display_map = {
        "Mirror": ("Reflection", "#FFE866"),
        "Constant": ("Constant", "#6FB8FF"),
        "Single": ("Single", "#FF8080"),
        "Per-Dst": ("Per-Destination", "#B580FF"),
        "Per-Con": ("Per-Connection", "#FF85C1"),
        "Per-Bucket": ("Per-Bucket", "#6EE66E"),
        "Per-CPU": ("Multi", "#66E0E0"),
        "Random": ("Random", "#FFB266"),
        "Fallback": ("Unclassified", "#CCCCCC"),
    }

    order_index = {k: i for i, k in enumerate(display_map)}

    all_classes = sorted(
        set(data1.keys()).union(data2.keys()).union(data3.keys()),
        key=lambda c: order_index.get(c, 999),
    )

    values1 = [float(data1.get(c, 0.0)) for c in all_classes]
    values2 = [float(data2.get(c, 0.0)) for c in all_classes]
    values3 = [float(data3.get(c, 0.0)) for c in all_classes]

    # --- Plot-Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    # --- Geometrie (3 Bars: von unten nach oben) ---
    # Reihenfolge: unten = msm_path_3, Mitte = msm_path_2, oben = msm_path_1
    data_sets = [values3, values2, values1]
    labels = ["RT-based &\nConnection-oriented", "Fixed-Interval", "RT-based"]
    n_bars = len(data_sets)

    total_height = 2 * y_padding + n_bars * bar_height + max(n_bars - 1, 0) * bar_gap
    y_positions = [
        y_padding + bar_height / 2 + i * (bar_height + bar_gap)
        for i in range(n_bars)
    ]

    fig_width = 5.0
    fig, ax = plt.subplots(figsize=(fig_width, total_height))

    # --- Bars zeichnen ---
    bars = []
    top_y = y_positions[-1]  # obere Bar = RTT-based (values1)
    mid_y = y_positions[-2]  # mittlere Bar = Fixed-Interval (values2)
    fallback_start = fallback_end = None

    for y, values in zip(y_positions, data_sets):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = display_map.get(cls, ("?", "#CCCCCC"))[1]
            bar = ax.barh(
                y, val, left=left, height=bar_height,
                edgecolor="none", color=color,
            )
            current_bars.append(bar)

            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",
                    ha="center", va="center",
                    fontsize=9, color="black",
                )

            # Unclassified-Bereich der oberen Bar (RTT-based) merken
            if y == top_y and cls == "Fallback":
                fallback_start = left
                fallback_end = left + val

            left += val
        bars = current_bars

    # --- Verbindung Unclassified (obere Bar) zu voller Breite (mittlere Bar) ---
    if fallback_start is not None and fallback_end is not None:
        y_upper = top_y - bar_height / 2  # untere Kante obere Bar
        y_lower = mid_y + bar_height / 2  # obere Kante mittlere Bar

        ax.plot([fallback_start, 0],
                [y_upper, y_lower],
                color="gray", linestyle="--", linewidth=0.8, alpha=0.5)

        ax.plot([fallback_end, 100],
                [y_upper, y_lower],
                color="gray", linestyle="--", linewidth=0.8, alpha=0.5)

        ax.fill_betweenx(
            [y_upper, y_lower],
            [fallback_start, 0],
            [fallback_end, 100],
            color="lightgray", alpha=0.5,
        )

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(0, total_height)

    ax.set_xlabel("IP-ID Selection Strategy [%]", labelpad=2)
    ax.set_ylabel("Measurement Type", rotation=90, labelpad=6)

    ax.xaxis.set_minor_locator(MultipleLocator(5))
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    # --- Legende ---
    legend_labels = [display_map.get(c, (c, None))[0] for c in all_classes]
    ax.legend(
        [b[0] for b in bars],
        legend_labels,
        loc="lower center",
        bbox_to_anchor=(0.35, 1.0),
        bbox_transform=ax.transAxes,
        ncol=5,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    # --- Speichern ---
    out_path = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_pattern_distribution.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    print(f"[+] Combined horizontal stacked bar plot saved to {out_path}")


def plot_pattern_distribution_acm_style_rst(
        msm_path_1: str,
        msm_path_2: str,
        msm_path_3: str,
        name: str,
        bar_height: float = 0.2,
        bar_gap: float = 0.2,
        y_padding: float = 0.1,
):
    # --- Load data ---
    def _load_data(msm_path):
        data_path = os.path.join(msm_path, "pattern_distribution", "data.pkl")
        with open(data_path, "rb") as f:
            data = pickle.load(f)
        if isinstance(data, pd.DataFrame):
            data = dict(zip(data["class"], data["relative"]))
        return data

    data1 = _load_data(msm_path_1)
    data2 = _load_data(msm_path_2)
    data3 = _load_data(msm_path_3)

    # --- Map classes ---
    display_map = {
        "Mirror": ("Reflection", "#FFE866"),
        "Constant": ("Constant", "#6FB8FF"),
        "Single": ("Single", "#FF8080"),
        "Per-Dst": ("Per-Destination", "#B580FF"),
        "Per-Con": ("Per-Connection", "#FF85C1"),
        "Per-Bucket": ("Per-Bucket", "#6EE66E"),
        "Per-CPU": ("Multi", "#66E0E0"),
        "Random": ("Random", "#FFB266"),
        "Fallback": ("Unclassified", "#CCCCCC"),
    }

    order_index = {k: i for i, k in enumerate(display_map)}

    all_classes = sorted(
        set(data1.keys()).union(data2.keys()).union(data3.keys()),
        key=lambda c: order_index.get(c, 999),
    )

    values1 = [float(data1.get(c, 0.0)) for c in all_classes]
    values2 = [float(data2.get(c, 0.0)) for c in all_classes]
    values3 = [float(data3.get(c, 0.0)) for c in all_classes]

    # --- Plot-Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    # --- Geometrie (3 Bars, von unten nach oben) ---
    # Reihenfolge: unten = msm_path_3 (RST-ACK), Mitte = msm_path_2 (SYN-ACK),
    #              oben  = msm_path_1 (SYN-ACK/RST-ACK)
    data_sets = [values3, values2, values1]
    labels = ["RST-ACK", "SYN-ACK", "SYN-ACK/RST-ACK"]
    n_bars = len(data_sets)

    total_height = 2 * y_padding + n_bars * bar_height + max(n_bars - 1, 0) * bar_gap
    y_positions = [
        y_padding + bar_height / 2 + i * (bar_height + bar_gap)
        for i in range(n_bars)
    ]

    fig_width = 5.0
    fig, ax = plt.subplots(figsize=(fig_width, total_height))

    # --- Bars zeichnen ---
    bars = []
    for y, values in zip(y_positions, data_sets):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = display_map.get(cls, ("?", "#CCCCCC"))[1]
            bar = ax.barh(
                y, val, left=left, height=bar_height,
                edgecolor="none", color=color,
            )
            current_bars.append(bar)

            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",
                    ha="center", va="center",
                    fontsize=9, color="black",
                )
            left += val
        bars = current_bars

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(0, total_height)

    ax.set_xlabel("IP-ID Selection Strategy [%]", labelpad=2)
    ax.set_ylabel("TCP Flags", rotation=90, labelpad=6)

    ax.xaxis.set_minor_locator(MultipleLocator(5))
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    # --- Legende ---
    legend_labels = [display_map.get(c, (c, None))[0] for c in all_classes]
    ax.legend(
        [b[0] for b in bars],
        legend_labels,
        loc="lower center",
        bbox_to_anchor=(0.35, 1.0),
        bbox_transform=ax.transAxes,
        ncol=5,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    # --- Speichern ---
    out_path = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_pattern_distribution.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    print(f"[+] Combined horizontal stacked bar plot saved to {out_path}")


def plot_pattern_distribution_acm_style_old(
        msm_path_1: str,
        msm_path_2: str,
        name: str,
        bar_height: float = 0.2,
        bar_gap: float = 0.2,
        y_padding: float = 0.1,
):
    # --- Load data ---
    def _load_data(msm_path):
        data_path = os.path.join(msm_path, "analysis", "pattern_distribution", "data.pkl")
        with open(data_path, "rb") as f:
            data = pickle.load(f)
        if isinstance(data, pd.DataFrame):
            data = dict(zip(data["class"], data["relative"]))
        return data

    data1 = _load_data(msm_path_1)
    data2 = _load_data(msm_path_2)

    # --- Map classes ---
    display_map = {
        "Mirror": ("Reflection", "#FFE866"),
        "Constant": ("Constant", "#6FB8FF"),
        "Single": ("Single", "#FF8080"),
        "Per-Dst": ("Per-Destination", "#B580FF"),
        "Per-Con": ("Per-Connection", "#FF85C1"),
        "Per-Bucket": ("Per-Bucket", "#6EE66E"),
        "Per-CPU": ("Multi", "#66E0E0"),
        "Random": ("Random", "#FFB266"),
        "Fallback": ("Unclassified", "#CCCCCC"),
    }

    order_index = {k: i for i, k in enumerate(display_map)}

    all_classes = sorted(
        set(data1.keys()).union(data2.keys()),
        key=lambda c: order_index.get(c, 999),
    )

    values1 = [float(data1.get(c, 0.0)) for c in all_classes]
    values2 = [float(data2.get(c, 0.0)) for c in all_classes]

    # --- Plot-Style ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    # --- Geometrie (zwei Bars: RTT-based oben, Fixed-Interval unten) ---
    data_sets = [values2, values1]  # Reihenfolge bottom -> top
    labels = ["Fixed-Interval", "RT-based"]  # passend zu data_sets
    n_bars = len(data_sets)

    total_height = 2 * y_padding + n_bars * bar_height + max(n_bars - 1, 0) * bar_gap
    y_positions = [
        y_padding + bar_height / 2 + i * (bar_height + bar_gap)
        for i in range(n_bars)
    ]

    fig_width = 5.0
    fig, ax = plt.subplots(figsize=(fig_width, total_height))

    # --- Bars zeichnen + Unclassified-Bereich der oberen Bar merken ---
    bars = []
    top_y = y_positions[-1]  # obere Bar = RTT-based
    fallback_start = fallback_end = None

    for y, values in zip(y_positions, data_sets):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = display_map.get(cls, ("?", "#CCCCCC"))[1]
            bar = ax.barh(
                y, val, left=left, height=bar_height,
                edgecolor="none", color=color,
            )
            current_bars.append(bar)

            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",
                    ha="center", va="center",
                    fontsize=9, color="black",
                )

            # Unclassified-Bereich der oberen Bar (RTT-based) merken
            if y == top_y and cls == "Fallback":
                fallback_start = left
                fallback_end = left + val

            left += val
        bars = current_bars

    # --- Verbindungslinien + schattierte Fläche zwischen beiden Bars ---
    if fallback_start is not None and fallback_end is not None:
        top_bottom_edge = top_y - bar_height / 2  # untere Kante obere Bar
        bot_top_edge = y_positions[0] + bar_height / 2  # obere Kante untere Bar

        # linke Linie: von Fallback-Start (oben) zu x=0 (unten)
        ax.plot([fallback_start, 0],
                [top_bottom_edge, bot_top_edge],
                color="gray", linestyle="--", linewidth=0.8, alpha=0.5)

        # rechte Linie: von Fallback-Ende (oben) zu x=100 (unten)
        ax.plot([fallback_end, 100],
                [top_bottom_edge, bot_top_edge],
                color="gray", linestyle="--", linewidth=0.8, alpha=0.5)

        # schattierte Fläche
        ax.fill_betweenx(
            [top_bottom_edge, bot_top_edge],
            [fallback_start, 0],
            [fallback_end, 100],
            color="lightgray", alpha=0.5,
        )

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(0, total_height)

    ax.set_xlabel("IP-ID Selection Strategy [%]", labelpad=2)
    ax.set_ylabel("Measurement Type", rotation=90, labelpad=6)

    ax.xaxis.set_minor_locator(MultipleLocator(5))
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    # --- Legende ---
    legend_labels = [display_map.get(c, (c, None))[0] for c in all_classes]
    ax.legend(
        [b[0] for b in bars],
        legend_labels,
        loc="lower center",
        bbox_to_anchor=(0.4, 1.0),
        bbox_transform=ax.transAxes,
        ncol=5,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    # --- Speichern ---
    out_path = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_pattern_distribution.pdf")
    plt.savefig(out_path, format="pdf", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    print(f"[+] Combined horizontal stacked bar plot saved to {out_path}")


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


def analyze_traceroute_device_behavior(caida_itdk_path: str, msm_path: str, t: int | None, d: int | None, name: str):
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
    conditions = []

    if t is not None:
        conditions.append(f"m.T = {int(t)}")

    if d is not None:
        conditions.append(f"m.D = {int(d)}")

    where_clause = ""
    if conditions:
        where_clause = "where " + " and ".join(conditions)

    con.execute(f"""
        create view joined as
        select e.IP_ID_PATTERN
        from eval e
        join ip_to_node m on e.IP = m.IP
        {where_clause}
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
    if os.path.lexists(dst):
        os.remove(dst)
    if os.path.islink(src):
        target = os.readlink(src)
        os.symlink(target, dst)
    else:
        shutil.copy(src, dst)

    print(f"Merged {path_a} & {path_b} => {out_path}")
    print(f"Rerun analysis of {out_path} to get merged results!")


def plot_transit_endhost_distribution_acm_style(
        msm_path: str,
        name: str,
        show_dst_only: bool = True,
        bar_height: float = 0.2,
        bar_gap: float = 0.2,
        y_padding: float = 0.1,
):
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

    # --- Map classes ---
    display_map = {
        "Mirror": ("Reflection", "#FFE866"),
        "Constant": ("Constant", "#6FB8FF"),
        "Single": ("Single", "#FF8080"),
        "Per-Dst": ("Per-Destination", "#B580FF"),
        "Per-Con": ("Per-Connection", "#FF85C1"),
        "Per-Bucket": ("Per-Bucket", "#6EE66E"),
        "Per-CPU": ("Multi", "#66E0E0"),
        "Random": ("Random", "#FFB266"),
        "Fallback": ("Unclassified", "#CCCCCC"),
    }

    order_index = {k: i for i, k in enumerate(display_map)}

    all_classes = sorted(
        set(transit_data.keys()).union(endhost_data.keys()),
        key=lambda c: order_index.get(c, 999),
    )

    transit_values = [float(transit_data.get(c, 0.0)) for c in all_classes]
    endhost_values = [float(endhost_data.get(c, 0.0)) for c in all_classes]

    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    # --- Geometrie ---
    data_sets = []
    labels = []

    if show_dst_only:
        data_sets.append(endhost_values)
        labels.append("All Others")

    data_sets.append(transit_values)
    labels.append("Router")

    n_bars = len(data_sets)

    # bar_gap wirkt nur zwischen Bars -> max(n_bars - 1, 0)
    total_height = 2 * y_padding + n_bars * bar_height + max(n_bars - 1, 0) * bar_gap

    y_positions = [
        y_padding + bar_height / 2 + i * (bar_height + bar_gap)
        for i in range(n_bars)
    ]

    # --- Figure: feste Breite, Höhe direkt = total_height in Zoll ---
    # Damit entsprechen bar_height/bar_gap/y_padding exakt Zoll in der Figure
    fig_width = 5.0
    fig, ax = plt.subplots(figsize=(fig_width, total_height))

    bars = []
    for y, values in zip(y_positions, data_sets):
        left = 0
        current_bars = []
        for cls, val in zip(all_classes, values):
            color = display_map.get(cls, ("?", "#CCCCCC"))[1]
            bar = ax.barh(
                y, val,
                left=left,
                height=bar_height,
                edgecolor="none",
                color=color
            )
            current_bars.append(bar)

            if val >= 1:
                ax.text(
                    left + val / 2, y,
                    f"{int(math.floor(val + 0.5))}",
                    ha="center", va="center",
                    fontsize=9, color="black"
                )
            left += val
        bars = current_bars

    # --- Achsen ---
    ax.set_xlim(0, 100)
    ax.set_ylim(0, total_height)

    ax.set_xlabel("IP-ID Selection Strategy [%]")
    # y-Label horizontal, damit es die Achsenhöhe nicht aufdehnt
    ax.set_ylabel("Device Type", rotation=90, labelpad=6)

    ax.xaxis.set_minor_locator(MultipleLocator(5))
    ax.tick_params(axis="x", which="minor", length=2, width=0.5)

    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.grid(axis="x", linestyle="--", linewidth=0.4, alpha=0.5)

    legend_labels = [display_map.get(c, (c, None))[0] for c in all_classes]
    ax.legend(
        [b[0] for b in bars],
        legend_labels,
        loc="lower center",
        bbox_to_anchor=(0.42, 1.0) if show_dst_only else (0.44, 1.4),
        bbox_transform=ax.transAxes,
        ncol=5,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    # KEIN tight_layout -> sonst wird die Achsenhöhe wieder verändert
    output_path = os.path.join(EXPERIMENTAL_RESULTS, f"{name}_transit_endhost_distribution.pdf")
    plt.savefig(output_path, format="pdf", bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)

    print(f"[+] Transit/Endhost ACM-style distribution saved to {output_path}")


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
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
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
    # --- Pfade ---
    data_path = os.path.join(msm_path, "analysis", "rtt_per_continent", "data.pkl")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Data file not found: {data_path}")

    output_dir = os.path.join(msm_path, "analysis", "rtt_per_continent")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "plot_acm_style.pdf")

    # --- Daten laden ---
    df = pd.read_pickle(data_path)

    # --- Display-Mapping: raw_name -> display_name ---
    display_map = {
        "Europe": "Europe",
        "North America": "N.America",
        "Asia": "Asia",
        "South America": "S.America",
        "Africa": "Africa",
        "Oceania": "Oceania",
    }
    df["continent"] = df["continent"].map(lambda c: display_map.get(c, c))

    # --- Outlier-Filter pro Kontinent (oberes 0.5%-Quantil entfernen) ---
    df = (
        df.groupby("continent", group_keys=False)
        .apply(lambda g: g[g["rtts"] <= g["rtts"].quantile(0.995 / 0.999)])
        .reset_index(drop=True)
    )

    # --- Reihenfolge: nach Sample-Count (descending) ---
    order = df["continent"].value_counts().index.tolist()

    # --- Plot-Style (konsistent mit anderen ACM-Plots) ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(5.2, 2.2))

    sns.violinplot(
        data=df,
        x="continent",
        y="rtts",
        order=order,
        inner="quartile",
        density_norm="width",
        linewidth=0.5,
        cut=0,
        color="#6FB8FF",
        ax=ax,
    )

    # --- Achsen ---
    ax.set_xlabel("")
    ax.set_ylabel("Average RTT [ms]", labelpad=4)
    ax.set_ylim(bottom=0)

    ax.set_xticks(range(len(order)))
    ax.set_xticklabels(order, rotation=0, ha="center")

    ax.grid(True, axis="y", linestyle="--", linewidth=0.4, alpha=0.5)
    ax.tick_params(width=0.5, length=2)

    for spine in ax.spines.values():
        spine.set_linewidth(0.5)
        spine.set_color("black")

    plt.tight_layout(pad=0.4)
    plt.savefig(output_file, format="pdf", bbox_inches="tight", dpi=300, pad_inches=0.02)
    plt.close(fig)

    print(f"[+] ACM-style RTT violin plot saved to {output_file}")


def plot_increment_cdfs_acm_style(msm_path: str, patterns: list[Pattern]):
    # --- Klassen-Mapping ---
    display_map = {
        "Mirror": ("Reflection", "#FFE866"),
        "Constant": ("Constant", "#6FB8FF"),
        "Single": ("Single", "#FF8080"),
        "Per-Dst": ("Per-Destination", "#B580FF"),
        "Per-Con": ("Per-Connection", "#FF85C1"),
        "Per-Bucket": ("Per-Bucket", "#6EE66E"),
        "Per-CPU": ("Multi", "#66E0E0"),
        "Random": ("Random", "#FFB266"),
        "Fallback": ("Unclassified", "#CCCCCC"),
    }
    order_index = {k: i for i, k in enumerate(display_map)}

    # --- Daten laden ---
    datasets: list[tuple[str, np.ndarray]] = []  # (raw_name, increments)
    for pattern in patterns:
        raw_name = pattern.value
        data_path = os.path.join(
            msm_path, "analysis", "inc_distribution",
            raw_name.lower().replace(" ", ""),
            "data.npy",
        )
        if not os.path.exists(data_path):
            print(f"[!] Skipping {raw_name}: no data file found.")
            continue

        increments = np.load(data_path)
        if increments.size == 0:
            print(f"[!] Skipping {raw_name}: empty data.")
            continue

        # 99.9-Perzentil clip (entfernt extreme Tails)
        q = np.quantile(increments, 0.999)
        increments = increments[increments <= q]
        datasets.append((raw_name, increments))

    if not datasets:
        print("[!] No data to plot.")
        return

    # In Display-Map-Reihenfolge sortieren
    datasets.sort(key=lambda d: order_index.get(d[0], 999))

    # --- Plot-Style (konsistent mit den anderen ACM-Plots) ---
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Latin Modern Roman"],
        "mathtext.fontset": "cm",
        "font.size": 10,
        "axes.linewidth": 0.8,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "pdf.fonttype": 42,
    })

    fig, ax = plt.subplots(figsize=(4.5, 2.0))

    # --- Kurven zeichnen ---
    for raw_name, increments in datasets:
        display_name, color = display_map.get(raw_name, (raw_name, "#808080"))
        sorted_vals = np.sort(increments)
        cdf = np.arange(1, len(sorted_vals) + 1) / len(sorted_vals) * 100

        ax.step(
            sorted_vals, cdf,
            where="post",
            label=display_name,
            linewidth=1.4,
            color=color,
        )

    # --- Achsen ---
    ax.set_xscale("log")
    ax.set_xlim(left=0.891251)

    # Y Major-Ticks (alle 20%)
    y_major = np.arange(0, 101, 20)
    ax.set_yticks(y_major)
    y_minor = y_major[:-1] + 10
    ax.set_yticks(y_minor, minor=True)
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_ylim(0, 105)

    ax.set_xlabel("IP-ID Increment", labelpad=2)
    ax.set_ylabel("Cumulative Percentage [%]", labelpad=2)

    ax.grid(True, which="major", linestyle="--", linewidth=0.4, alpha=0.5)
    ax.grid(True, which="minor", linestyle=":", linewidth=0.3, alpha=0.3)

    ax.tick_params(axis="both", which="major", length=3, width=0.5)
    ax.tick_params(axis="both", which="minor", length=1.5, width=0.5)

    for spine in ax.spines.values():
        spine.set_linewidth(0.5)

    # --- Legende oben ---
    ax.legend(
        loc="lower center",
        bbox_to_anchor=(0.5, 1.0),
        bbox_transform=ax.transAxes,
        ncol=4,
        frameon=False,
        handlelength=1.0,
        handletextpad=0.2,
        columnspacing=0.8,
    )

    plt.tight_layout(pad=0.4)

    # --- Speichern ---
    output_dir = os.path.join(msm_path, "analysis", "inc_distribution")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "plot_cdf_multi_acm_style.pdf")

    plt.savefig(output_file, format="pdf", bbox_inches="tight", dpi=300, pad_inches=0.02)
    plt.close(fig)

    print(f"[+] Multi-pattern ACM-style CDF saved to {output_file}")


if __name__ == "__main__":
    main()
