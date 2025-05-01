import os
import subprocess
import tempfile
import time

import polars
import polars as pl

from core.utils import config

ip_zmap_name = "saddr"
ts_zmap_name = "timestamp_ts"

zmap_output_fields = ",".join([ip_zmap_name, ts_zmap_name])


def log_runtime(start: float) -> str:
    elapsed = int(time.time() - start)
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        runtime = f"{hours}h{minutes}m{seconds}s"
    elif minutes > 0:
        runtime = f"{minutes}m{seconds}s"
    else:
        runtime = f"{seconds}s"
    return f"runtime=[{runtime}]"


def compress_csv(input_csv: str) -> str:
    compressed_output_file = input_csv + ".zst"
    subprocess.run(["zstd", "-T0", "--rm", input_csv], check=True)
    return compressed_output_file


def decompress_csv(input_csv: str) -> str:
    decompressed_output_file = input_csv.replace(".zst", "")
    subprocess.run(["zstd", "-d", "-T0", input_csv], check=True)
    return decompressed_output_file


def deduplicate_csv(lf: polars.LazyFrame, total_rows: int, column_name: str) -> (int, float):
    lf = lf.unique(subset=[column_name], keep="first")
    unique_rows = lf.select(pl.count()).collect().item()
    removed_rows = total_rows - unique_rows
    removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0
    return removed_rows, removed_rows_percent


def deduplicate_csv_linux_low_ram(input_csv: str, total_rows: int, column_name: str) -> (int, float):
    sort_csv_linux_low_ram(input_csv=input_csv, column_name=column_name)
    unique_rows = count_rows_linux_low_ram(input_csv)
    removed_rows = total_rows - unique_rows
    removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0
    return removed_rows, removed_rows_percent


def read_csv_header_linux_low_ram(input_csv: str) -> str:
    result = subprocess.check_output(['head', '-n', '1', input_csv], text=True)
    return result.strip()


def replace_csv_header_linux_low_ram(input_csv: str, new_header: str) -> bool:
    try:
        subprocess.run(
            ['sed', '-i', f'1s/.*/{new_header}/', input_csv],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def count_rows_linux_low_ram(input_csv: str) -> int:
    result = subprocess.check_output(['wc', '-l', input_csv], text=True)
    return int(result.strip().split()[0])


def sort_csv_linux_low_ram(input_csv: str, column_name: str) -> bool:
    # Find the column index that matches column_name
    try:
        header = subprocess.check_output(
            ['head', '-n', '1', input_csv], text=True
        ).strip()
        columns = header.split(',')
        column_index = columns.index(column_name) + 1  # +1 for 1-based indexing

        # Create a temporary file
        temp_csv = tempfile.mktemp(prefix=f"{input_csv}.sort.", dir=".")

        # Run the sort command to sort by the found column index
        subprocess.run(
            ['sort', '-t', ',', f'-k{column_index},{column_index}', '-u', '-T', '.', input_csv],
            stdout=open(temp_csv, 'w'),
            check=True
        )

        # Replace the original CSV with the sorted version
        os.rename(temp_csv, input_csv)
        return True
    except (subprocess.CalledProcessError, ValueError):
        return False


def cleanup(targets_file: str):
    overall_start = time.time()

    print(f"Cleanup {targets_file}")

    lf = None
    if not config.is_linux_low_ram:
        lf = pl.scan_csv(targets_file)

    print("Verifying required columns exist in the CSV file...")
    required_columns = [ip_zmap_name, ts_zmap_name]
    if config.is_linux_low_ram:
        header_line = read_csv_header_linux_low_ram(targets_file)
        missing_columns = [col for col in required_columns if col not in header_line.split(',')]
    else:
        schema = lf.collect_schema()
        missing_columns = [col for col in required_columns if col not in schema.names()]
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
            sort_csv_linux_low_ram(input_csv=targets_file, column_name=ts_zmap_name)
        else:
            lf = lf.sort(ts_zmap_name)
        print(f"Sorting finished: {log_runtime(start)}")

        # Rename
        start = time.time()
        print("Renaming columns...")
        if config.is_linux_low_ram:
            replace_csv_header_linux_low_ram(input_csv=targets_file,
                                             new_header=f"{config.ip_col_name},{config.ts_ip_col_name}")
        else:
            lf = lf.rename({
                ip_zmap_name: config.ip_col_name,
                ts_zmap_name: config.ts_ip_col_name
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
        # start = time.time()
        # print("Analyzing ZMap response rate...")
        # analyze_response_rate(targets_file=compressed_output_file, ts_name=config.ts_ip_col_name)
        # print(f"Analyzing finished: {log_runtime(start)}")

        print(f"Cleanup finished: {log_runtime(overall_start)}")
        print(f"Results saved in {compressed_file}")

    except Exception as e:
        print(f"Error during processing: {str(e)}")
