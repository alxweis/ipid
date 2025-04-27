import os
import subprocess
import time

import polars as pl

ip_zmap_name = "saddr"
ts_zmap_name = "timestamp_ts"
ip_col_name = "IP"
ts_col_name = "TS_IP"

zmap_output_fields = ",".join([ip_zmap_name, ts_zmap_name])


def cleanup(output_file: str):
    start_time = time.time()

    temp_output_file = output_file + ".temp"
    compr_output_file = output_file + ".zst"

    print(f"Processing file: {output_file}")

    # Verify required columns exist in the CSV file
    required_columns = [ip_zmap_name, ts_zmap_name]
    lf = pl.scan_csv(output_file)
    schema = lf.collect_schema()
    missing_columns = [col for col in required_columns if col not in schema.names()]
    if missing_columns:
        print(f"Error: Missing required columns: {', '.join(missing_columns)}")
        return

    # Count total rows in the file
    total_rows = lf.select(pl.count()).fetch().item()
    print(f"Total rows in original file: {total_rows}")

    try:
        # Deduplicate by IP address and keep the first occurrence
        deduplicated_lf = lf.unique(subset=[ip_zmap_name], keep="first")

        # Sort rows by timestamp
        sorted_lf = deduplicated_lf.sort(ts_zmap_name)

        # Rename columns for clarity
        renamed_lf = sorted_lf.rename({
            ip_zmap_name: ip_col_name,
            ts_zmap_name: ts_col_name
        })

        # Write the cleaned data to a temporary file
        renamed_lf.sink_csv(temp_output_file)

        # Check how many unique IPs were processed
        unique_count = renamed_lf.select(pl.count()).fetch().item()

        # Calculate and display duplicate statistics
        duplicates = total_rows - unique_count
        duplicate_percent = (duplicates / total_rows * 100) if total_rows > 0 else 0
        print(f"Unique IP addresses: {unique_count}")
        print(f"Removed duplicate rows: {duplicates} ({duplicate_percent:.2f}%)")

        # Display timestamp range for verification
        min_ts = renamed_lf.select(pl.col(ts_col_name).min()).fetch().item()
        max_ts = renamed_lf.select(pl.col(ts_col_name).max()).fetch().item()
        print(f"Timestamp range: {min_ts} to {max_ts}")

        # Replace the original file with the cleaned data
        os.remove(output_file)
        os.rename(temp_output_file, output_file)
        print(f"Original file replaced with the cleaned version.")

        # Compress the cleaned file with ZSTD
        print(f"Compressing file with ZSTD...")

        try:
            original_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
            subprocess.run(["zstd", "-T0", "--rm", output_file], check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            print(f"Compression complete. File saved as: {compr_output_file}")

            # Calculate and display compression ratio
            compressed_size = os.path.getsize(compr_output_file)
            compression_ratio = original_size / compressed_size if compressed_size > 0 else 0
            print(f"Compression ratio: {compression_ratio:.2f}x")

        except subprocess.CalledProcessError as e:
            print(f"ZSTD compression failed: {e.stderr.decode() if e.stderr else str(e)}")
            print("The cleaned file was saved but not compressed.")

        except FileNotFoundError:
            print("ZSTD not found. Please install ZSTD or add it to your PATH.")
            print("The cleaned file was saved but not compressed.")

        # analyze_response_rate(targets_file=compr_output_file, ts_name=ts_col_name)

        # Output processing time
        elapsed_time = time.time() - start_time
        print(f"Total processing completed in {elapsed_time:.2f} seconds.")
        print(f"Results saved in {compr_output_file}")

    except Exception as e:
        print(f"Error during processing: {str(e)}")

        # Clean up temporary file if it exists
        if os.path.exists(temp_output_file):
            os.remove(temp_output_file)
