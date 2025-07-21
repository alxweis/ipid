import time

from core.utils import config, compress_file, runtime
from hitlist import get_header_csv, replace_header_csv, count_rows, deduplicate_csv, sort_csv

ip_zmap_name = "saddr"
ts_zmap_name = "timestamp_ts"
us_zmap_name = "timestamp_us"

zmap_output_columns = [ip_zmap_name, ts_zmap_name, us_zmap_name]
zmap_output_fields = ",".join(zmap_output_columns)


def cleanup(targets_file: str) -> str | None:
    overall_start = time.time()

    print(f"Cleanup {targets_file}")

    print("Verifying required columns exist in the CSV file...")
    header_line = get_header_csv(targets_file)
    missing_columns = [col for col in zmap_output_columns if col not in header_line.split(',')]
    if missing_columns:
        print(f"Error: Missing required columns: {', '.join(missing_columns)}")
        return None

    print("Count total rows in the file...")
    total_rows = count_rows(targets_file)
    print(f"Total rows: {total_rows}")

    try:
        # Deduplicate
        start = time.time()
        print("Deduplicating by IP address...")
        removed_rows, removed_rows_percent = deduplicate_csv(input_csv=targets_file, total_rows=total_rows,
                                                             column_name=ip_zmap_name)
        print(f"Deduplicating finished: {runtime(start)} removed_rows=[{removed_rows},{removed_rows_percent:.2f}%]")

        # Sort
        start = time.time()
        print("Sorting by timestamp...")
        sort_csv(input_csv=targets_file, column_names=[ts_zmap_name, us_zmap_name], remove_duplicates=False)
        print(f"Sorting finished: {runtime(start)}")

        # Rename
        start = time.time()
        print("Renaming columns...")
        replace_header_csv(input_csv=targets_file,
                           new_header=f"{config.ip_col_name},{config.ts_ip_col_name},{config.us_ip_col_name}")
        print(f"Renaming finished: {runtime(start)}")

        # Compress
        start = time.time()
        print("Compressing file with zstd...")
        result_file = compress_file(targets_file)
        print(f"Compressing finished: {runtime(start)}")

        print(f"Cleanup finished: {runtime(overall_start)}")
        return result_file

    except Exception as e:
        print(f"Error during processing: {str(e)}")


def post_cleanup(targets_file: str) -> str | None:
    overall_start = time.time()

    print(f"Cleanup {targets_file}")

    print("Verifying required columns exist in the CSV file...")
    header_line = get_header_csv(targets_file)
    missing_columns = [col for col in [config.ip_col_name, config.ts_ip_col_name, config.us_ip_col_name] if
                       col not in header_line.split(',')]
    if missing_columns:
        print(f"Error: Missing required columns: {', '.join(missing_columns)}")
        return None

    print("Count total rows in the file...")
    total_rows = count_rows(targets_file)
    print(f"Total rows: {total_rows}")

    try:
        # Deduplicate
        start = time.time()
        print("Deduplicating by IP address...")
        removed_rows, removed_rows_percent = deduplicate_csv(input_csv=targets_file, total_rows=total_rows,
                                                             column_name=config.ip_col_name)
        print(f"Deduplicating finished: {runtime(start)} removed_rows=[{removed_rows},{removed_rows_percent:.2f}%]")

        # Sort
        start = time.time()
        print("Sorting by timestamp...")
        sort_csv(input_csv=targets_file, column_names=[config.ts_ip_col_name, config.us_ip_col_name], remove_duplicates=False)
        print(f"Sorting finished: {runtime(start)}")

        # Compress
        start = time.time()
        print("Compressing file with zstd...")
        result_file = compress_file(targets_file)
        print(f"Compressing finished: {runtime(start)}")

        print(f"Cleanup finished: {runtime(overall_start)}")
        return result_file

    except Exception as e:
        print(f"Error during processing: {str(e)}")
