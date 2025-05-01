import os
import time

import polars as pl

from core.utils import config
from hitlist import get_csv_header_linux_low_ram, count_rows_linux_low_ram, deduplicate_csv_linux_low_ram, \
    deduplicate_csv, log_runtime, replace_csv_header_linux_low_ram, sort_csv_linux_low_ram, compress_csv

ip_zmap_name = "saddr"
ts_zmap_name = "timestamp_ts"
us_zmap_name = "timestamp_us"

zmap_output_columns = [ip_zmap_name, ts_zmap_name, us_zmap_name]
zmap_output_fields = ",".join(zmap_output_columns)


def cleanup(targets_file: str):
    overall_start = time.time()

    print(f"Cleanup {targets_file}")

    lf = None
    if not config.is_linux_low_ram:
        lf = pl.scan_csv(targets_file)

    print("Verifying required columns exist in the CSV file...")
    if config.is_linux_low_ram:
        header_line = get_csv_header_linux_low_ram(targets_file)
        missing_columns = [col for col in zmap_output_columns if col not in header_line.split(',')]
    else:
        schema = lf.collect_schema()
        missing_columns = [col for col in zmap_output_columns if col not in schema.names()]
    if missing_columns:
        print(f"Error: Missing required columns: {', '.join(missing_columns)}")
        return

    print("Count total rows in the file...")
    if config.is_linux_low_ram:
        total_rows = count_rows_linux_low_ram(targets_file)
    else:
        total_rows = lf.select(pl.count()).collect().item()
    print(f"Total rows: {total_rows}")

    try:
        # Deduplicate
        start = time.time()
        print("Deduplicating by IP address...")
        if config.is_linux_low_ram:
            removed_rows, removed_rows_percent = deduplicate_csv_linux_low_ram(input_csv=targets_file,
                                                                               total_rows=total_rows,
                                                                               column_name=ip_zmap_name)
        else:
            removed_rows, removed_rows_percent = deduplicate_csv(lf=lf, total_rows=total_rows, column_name=ip_zmap_name)
        print(f"Deduplicating finished: {log_runtime(start)} removed_rows=[{removed_rows},{removed_rows_percent:.2f}%]")

        # Sort
        start = time.time()
        print("Sorting by timestamp...")
        if config.is_linux_low_ram:
            sort_csv_linux_low_ram(input_csv=targets_file, column_names=[ts_zmap_name, us_zmap_name])
        else:
            lf = lf.sort([ts_zmap_name, us_zmap_name])
        print(f"Sorting finished: {log_runtime(start)}")

        # Rename
        start = time.time()
        print("Renaming columns...")
        if config.is_linux_low_ram:
            replace_csv_header_linux_low_ram(input_csv=targets_file,
                                             new_header=f"{config.ip_col_name},{config.ts_ip_col_name},{config.us_ip_col_name}")
        else:
            lf = lf.rename({
                ip_zmap_name: config.ip_col_name,
                ts_zmap_name: config.ts_ip_col_name,
                us_zmap_name: config.us_ip_col_name
            })
        print(f"Renaming finished: {log_runtime(start)}")

        if not config.is_linux_low_ram:
            # Write temp file
            start = time.time()
            print("Writing the cleaned data to a temporary file...")
            temp_output_file = targets_file + ".tmp"
            lf.sink_csv(temp_output_file)
            print(f"Writing finished: {log_runtime(start)}")

            # Replace file
            start = time.time()
            print("Replacing the original file with the cleaned version...")
            os.remove(targets_file)
            os.rename(temp_output_file, targets_file)
            print(f"Replacing finished: {log_runtime(start)}")

        # Compress
        start = time.time()
        print("Compressing file with ZSTD...")
        compressed_file = compress_csv(targets_file)
        print(f"Compressing finished: {log_runtime(start)} compressed_file=[{compressed_file}]")

        # # Analyze
        # analyze_response_rate(targets_file=compressed_output_file, ts_name=config.ts_ip_col_name)

        print(f"Cleanup finished: {log_runtime(overall_start)}")
        print(f"Results saved in {compressed_file}")

    except Exception as e:
        print(f"Error during processing: {str(e)}")
