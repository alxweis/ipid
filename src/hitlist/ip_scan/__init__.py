import os
import subprocess
import time

import polars as pl

from analysis.main import analyze_response_rate
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


def cleanup(output_file: str):
    overall_start = time.time()

    temp_output_file = output_file + ".temp"
    compressed_output_file = output_file + ".zst"

    print(f"Cleanup {output_file}")

    print("Verifying required columns exist in the CSV file...")
    required_columns = [ip_zmap_name, ts_zmap_name]
    lf = pl.scan_csv(output_file)
    schema = lf.collect_schema()
    missing_columns = [col for col in required_columns if col not in schema.names()]
    if missing_columns:
        print(f"Error: Missing required columns: {', '.join(missing_columns)}")
        return

    print("Count total rows in the file...")
    total_rows = lf.select(pl.count()).fetch().item()
    print(f"Total rows: {total_rows}")

    try:
        # Deduplicate
        start = time.time()
        print("Deduplicating by IP address...")
        lf = lf.unique(subset=[ip_zmap_name], keep="first")
        unique_rows = lf.select(pl.count()).fetch().item()
        removed_rows = total_rows - unique_rows
        removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0
        print(f"Deduplicating finished: {log_runtime(start)} removed_rows=[{removed_rows},{removed_rows_percent:.2f}%]")

        # Sort
        start = time.time()
        print("Sorting by timestamp...")
        lf = lf.sort(ts_zmap_name)
        print(f"Sorting finished: {log_runtime(start)}")

        # Rename
        start = time.time()
        print("Renaming columns...")
        lf = lf.rename({
            ip_zmap_name: config.ip_col_name,
            ts_zmap_name: config.ts_ip_col_name
        })
        print(f"Renaming finished: {log_runtime(start)}")

        # Write temp file
        start = time.time()
        print("Writing the cleaned data to a temporary file...")
        lf.sink_csv(temp_output_file)
        print(f"Writing finished: {log_runtime(start)}")

        # Replace file
        start = time.time()
        print("Replacing the original file with the cleaned version...")
        os.remove(output_file)
        os.rename(temp_output_file, output_file)
        print(f"Replacing finished: {log_runtime(start)}")

        # Compress
        start = time.time()
        print("Compressing file with ZSTD...")
        try:
            subprocess.run(["zstd", "-T0", "--rm", output_file], check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            print(f"Compressing finished: {log_runtime(start)} compressed_file=[{compressed_output_file}]")
        except subprocess.CalledProcessError as e:
            print(f"ZSTD compression failed: {e.stderr.decode() if e.stderr else str(e)}")
            print("The cleaned file was saved but not compressed.")
        except FileNotFoundError:
            print("ZSTD not found. Please install ZSTD or add it to your PATH.")
            print("The cleaned file was saved but not compressed.")

        # Analyze
        start = time.time()
        print("Analyzing ZMap response rate...")
        analyze_response_rate(targets_file=compressed_output_file, ts_name=config.ts_ip_col_name)
        print(f"Analyzing finished: {log_runtime(start)}")

        print(f"Cleanup finished: {log_runtime(overall_start)}")
        print(f"Results saved in {compressed_output_file}")

    except Exception as e:
        print(f"Error during processing: {str(e)}")
        if os.path.exists(temp_output_file):
            os.remove(temp_output_file)
