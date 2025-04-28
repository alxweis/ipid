from analysis.main import analyze_response_rate
from core.utils import config


def main():
    targets_file = "../../targets/icmp/2025-04-19_21-37-29/targets.csv"
    analyze_response_rate(targets_file=targets_file, ts_name=config.ts_ip_col_name)


if __name__ == "__main__":
    main()
