import os
import subprocess
import tempfile
import time

import polars as pl


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


def deduplicate_csv(lf: pl.LazyFrame, total_rows: int, column_name: str) -> (int, float):
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


def extract_column_no_header(input_csv: str, column_name: str, output_txt: str):
    header = subprocess.check_output(
        ['head', '-n', '1', input_csv], text=True
    ).strip()
    columns = header.split(',')
    column_index = columns.index(column_name) + 1  # +1 for 1-based indexing

    with open(input_csv, 'r') as f_in, open(output_txt, 'w') as f_out:
        next(f_in)  # skip header
        for line in f_in:
            f_out.write(line.split(',')[column_index-1] + '\n')
