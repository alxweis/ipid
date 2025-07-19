import os
import tempfile
import time

import duckdb

from core.utils import config, compress_file, runtime
from hitlist import get_header_csv, replace_header_csv

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

    try:
        # Deduplicating
        start = time.time()
        print("Deduplicating...")
        temp_file = tempfile.mktemp(prefix=f"{targets_file}.sort.", dir=".")
        con = duckdb.connect()

        con.execute(f"""
        CREATE TABLE raw AS 
        SELECT * FROM read_csv_auto('{targets_file}')
        """)

        con.execute(f"""
        CREATE TABLE unique_ip AS
        SELECT * FROM (
          SELECT *, ROW_NUMBER() OVER (PARTITION BY {ip_zmap_name} ORDER BY 1) AS rn FROM raw
        ) WHERE rn = 1
        """)

        con.execute(f"""
        COPY unique_ip TO '{temp_file}' (HEADER FALSE)
        """)

        con.close()

        os.replace(temp_file, targets_file)
        print(f"Deduplicating finished: {runtime(start)}")

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
