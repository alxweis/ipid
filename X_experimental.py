import os
import sys
from analysis.main import analyze_response_rate
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
    print("  1 - Analyze Sequence Stable Lengths (Synthetic):")
    print(f"    python {filename} 1 <sequence_count_per_pattern> <sequence_length>")
    print("  2 - Analyze Sequence Stable Lengths (Natural):")
    print(f"    python {filename} 2 <probing_csv_path>")
    print("  3 - Analyze Response Rate:")
    print(f"    python {filename} 3 <targets_file> <'ip'|'os'>")
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
        probing_csv = sys.argv[2]
        analyze_sequence_stable_lens_natural(probing_csv=probing_csv)
    elif mode == 3:
        if len(sys.argv) != 4:
            print_usage()
            return
        targets_file = sys.argv[2]
        ts_type = sys.argv[3]
        if ts_type == "ip":
            ts_name = config.ts_ip_col_name
        elif ts_type == "os":
            ts_name = config.ts_os_col_name
        else:
            print_usage()
            return

        analyze_response_rate(targets_file=targets_file, ts_name=ts_name)
    else:
        print_usage()


if __name__ == "__main__":
    main()
