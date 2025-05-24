import os
import sys

from analysis.main import plot_response_rate, calc_intersections
from experimental.sequence_stable_len_analysis.main import (
    analyze_sequence_stable_lens_synthetic,
    analyze_sequence_stable_lens_natural
)

filename = os.path.basename(__file__)


def print_usage():
    print("Usage:")
    print(f"  python {filename} <mode> [additional arguments]")
    print("\nModes:")
    print("  1 - Analyze Sequence Stable Lengths (Synthetic):")
    print(f"    python {filename} 1 <sequence_count_per_pattern> <sequence_length>")
    print("  2 - Analyze Sequence Stable Lengths (Natural):")
    print(f"    python {filename} 2 <result_path>")
    print("  3 - Analyze Response Rate for IP-Scan or OS-Scan:")
    print(f"    python {filename} 3 <targets_path> <ip|os>")
    print("  4 - Analyze Intersections:")
    print(f"    python {filename} 4 <ip|os> <targets_path> <targets_path> ...")
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
        if len(sys.argv) != 4:
            print_usage()
            return
        result_path = sys.argv[2]
        ts_type = sys.argv[3]

        if ts_type not in {"ip", "os"}:
            print_usage()
            return

        file_name = "targets.csv.zst" if ts_type == "ip" else "targets_os.csv.zst"
        targets_csv = os.path.join(result_path, file_name)
        plot_response_rate(targets_csv=targets_csv, ts_type=ts_type)
    elif mode == 4:
        if len(sys.argv) < 4:
            print_usage()
            return

        ts_type = sys.argv[2]
        if ts_type not in {"ip", "os"}:
            print_usage()
            return

        file_name = "targets.csv.zst" if ts_type == "ip" else "targets_os.csv.zst"
        targets_paths = [os.path.join(tps, file_name) for tps in sys.argv[3:]]
        calc_intersections(targets_paths, on="IP")
    else:
        print_usage()


if __name__ == "__main__":
    main()
