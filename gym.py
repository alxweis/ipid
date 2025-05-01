import time

import polars as pl

from hitlist import log_runtime


def deduplicate_csv_memory_efficient(targets_file: str, column_name: str) -> tuple[int, float]:
    try:
        # LazyFrame erstellen mit Streaming-Engine
        lf = pl.scan_csv(targets_file)

        # Gesamtzeilenzahl zählen mit Streaming
        total_rows = lf.select(pl.len()).collect(engine="streaming").item()

        # Deduplizieren mit Streaming-Engine
        unique_df = lf.unique(subset=[column_name], keep="first")
        unique_rows = unique_df.select(pl.len()).collect(engine="streaming").item()

        # Berechnung der entfernten Zeilen
        removed_rows = total_rows - unique_rows
        removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0

        return removed_rows, removed_rows_percent
    except Exception as e:
        print(f"Error while processing: {e}")
        return 0, 0.0


def main():
    start = time.time()
    print("Deduplicating by IP address...")
    removed_rows, removed_rows_percent = deduplicate_csv_memory_efficient(targets_file="targets/tcp/80/2025-04-29_22-32-07/targets.csv.zst", column_name="saddr")
    print(f"Deduplicating finished: {log_runtime(start)} removed_rows=[{removed_rows},{removed_rows_percent:.2f}%]")


if __name__ == "__main__":
    main()
