import time

from hitlist import log_runtime, deduplicate_csv_linux_low_ram, count_rows_linux_low_ram


def main():
    # Deduplicate
    targets_file = "targets/tcp/80/2025-04-29_22-32-07/targets.csv"

    start = time.time()
    print("Deduplicating by IP address...")

    total_rows = count_rows_linux_low_ram(targets_file)

    removed_rows, removed_rows_percent = deduplicate_csv_linux_low_ram(input_csv=targets_file, total_rows=total_rows,
                                                                       column_name="saddr")
    print(f"Deduplicating finished: {log_runtime(start)} removed_rows=[{removed_rows},{removed_rows_percent:.2f}%]")


if __name__ == "__main__":
    main()
