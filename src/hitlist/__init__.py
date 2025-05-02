import csv
import os
import subprocess
import tempfile
import time

import polars as pl

from core.utils import config


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
    subprocess.run(["zstd", "-T0", "-f", "--rm", input_csv], check=True)
    return compressed_output_file


def decompress_csv(input_csv: str) -> str:
    decompressed_output_file = input_csv.removesuffix(".zst")
    subprocess.run(["zstd", "-d", "-T0", "-f", input_csv], check=True)
    return decompressed_output_file


def deduplicate_csv(lf: pl.LazyFrame, total_rows: int, column_name: str) -> (int, float):
    lf = lf.unique(subset=[column_name], keep="first")
    unique_rows = lf.select(pl.count()).collect().item()
    removed_rows = total_rows - unique_rows
    removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0
    return removed_rows, removed_rows_percent


def deduplicate_csv_linux_low_ram(input_csv: str, total_rows: int, column_name: str) -> (int, float):
    sort_csv_linux_low_ram(input_csv=input_csv, column_names=[column_name])
    unique_rows = count_rows_linux_low_ram(input_csv)
    removed_rows = total_rows - unique_rows
    removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0
    return removed_rows, removed_rows_percent


def get_csv_header_linux_low_ram(input_csv: str) -> str:
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


def get_column_index(input_csv: str, column_name: str) -> int:
    header = subprocess.check_output(
        ['head', '-n', '1', input_csv], text=True
    ).strip()
    columns = header.split(',')
    column_index = columns.index(column_name)
    return column_index


def sort_csv_linux_low_ram(input_csv: str, column_names: list[str]) -> bool:
    try:
        # Hole die Spaltenindizes für alle angegebenen Spaltennamen
        column_indices = [get_column_index(input_csv=input_csv, column_name=col_name) for col_name in column_names]

        # Erstelle eine temporäre Datei
        temp_csv = tempfile.mktemp(prefix=f"{input_csv}.sort.", dir=".")

        # Bereite die Sortieroptionen vor
        sort_keys = [f'-k{index + 1},{index + 1}n' for index in column_indices]

        # Führe den Sortierbefehl aus, wobei mehrere Sortierschlüssel angegeben werden
        subprocess.run(
            ['sort', '-t', ',', *sort_keys, '-T', '.', input_csv],
            stdout=open(temp_csv, 'w'),
            check=True
        )

        # Ersetze die Originaldatei mit der sortierten Version
        os.rename(temp_csv, input_csv)
        return True
    except (subprocess.CalledProcessError, ValueError):
        return False


def extract_column_no_header(input_csv: str, column_name: str, output_txt: str):
    column_index = get_column_index(input_csv=input_csv, column_name=column_name)
    with open(input_csv, 'r') as f_in, open(output_txt, 'w') as f_out:
        next(f_in)  # skip header
        for line in f_in:
            f_out.write(line.split(',')[column_index] + '\n')


def join_csv_linux_low_ram(original_csv: str, join_csv: str, join_column_name: str) -> str:
    # Sort original_csv and join_csv by join_column_name
    sort_csv_linux_low_ram(input_csv=original_csv, column_names=[join_column_name])
    sort_csv_linux_low_ram(input_csv=join_csv, column_names=[join_column_name])

    merge_csv = original_csv + ".merge.tmp"

    orig_index = get_column_index(original_csv, join_column_name)
    join_index = get_column_index(join_csv, join_column_name)

    orig_header = get_csv_header_linux_low_ram(original_csv).split(',')
    join_header = [col for col in get_csv_header_linux_low_ram(join_csv).split(',') if col != join_column_name]
    merge_header = orig_header + join_header

    with open(original_csv, newline='', encoding='utf-8') as orig_f, \
            open(join_csv, newline='', encoding='utf-8') as join_f, \
            open(merge_csv, 'w', newline='', encoding='utf-8') as merge_f:

        orig_reader = csv.reader(orig_f)
        join_reader = csv.reader(join_f)
        merge_writer = csv.writer(merge_f)

        # skip headers
        next(orig_reader)
        next(join_reader)

        # write merged header
        merge_writer.writerow(merge_header)

        # init first join line
        try:
            join_row = next(join_reader)
        except StopIteration:
            join_row = None

        matched_count = 0

        for orig_row in orig_reader:
            if not join_row:
                break

            orig_val = orig_row[orig_index]
            join_val = join_row[join_index]

            if orig_val == join_val:
                modified_join_row = join_row[:join_index] + join_row[join_index + 1:]
                merged_row = orig_row + modified_join_row
                merge_writer.writerow(merged_row)
                matched_count += 1
                try:
                    join_row = next(join_reader)
                except StopIteration:
                    join_row = None

        print(f"Finished joining: matched_rows=[{matched_count}]")

    # Sort merge_csv by timestamp
    sort_csv_linux_low_ram(input_csv=merge_csv, column_names=[config.ts_ip_col_name, config.us_ip_col_name])

    os.replace(merge_csv, original_csv)
    return original_csv
