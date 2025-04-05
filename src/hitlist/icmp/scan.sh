#!/bin/bash

# Ensure OUTPUT_DIR and MAX_IPS are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <output_dir> <max_ips>"
    exit 1
fi

# Configuration
OUTPUT_DIR="$1"
MAX_IPS="$2"
OUTPUT_FILE="${OUTPUT_DIR}/targets.csv"
BANDWIDTH="100M"

# Function to count lines efficiently
count_lines() {
    wc -l < "$1"
}

cleanup() {
    # Replace 'saddr' with 'IP' in the header
    sed -i '1s/^saddr/IP/' "$OUTPUT_FILE"

    # Count initial IPs
    initial_count=$(count_lines "$OUTPUT_FILE")
    echo "Initial number of IPs (including header): $initial_count"

    # Deduplicate using sort -u
    start_dedup=$(date +%s)
    TEMP_FILE=$(mktemp "${OUTPUT_FILE}.dedup.XXXXXX")
    header=$(head -n 1 "$OUTPUT_FILE")
    { echo "$header"; tail -n +2 "$OUTPUT_FILE" | sort -u; } > "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    end_dedup=$(date +%s)
    dedup_time=$((end_dedup - start_dedup))

    deduped_count=$(count_lines "$OUTPUT_FILE")
    deduped_diff=$((initial_count - deduped_count))
    echo "Number of IPs removed by deduplication: $deduped_diff"

    # Shuffle using shuf
    start_shuffle=$(date +%s)
    TEMP_FILE=$(mktemp "${OUTPUT_FILE}.shuffle.XXXXXX")
    header=$(head -n 1 "$OUTPUT_FILE")
    { echo "$header"; tail -n +2 "$OUTPUT_FILE" | shuf; } > "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    end_shuffle=$(date +%s)
    shuffle_time=$((end_shuffle - start_shuffle))

    final_count=$(count_lines "$OUTPUT_FILE")
    echo "Final number of IPs (including header): $final_count"

    echo "Deduplication took: $dedup_time seconds"
    echo "Shuffling took: $shuffle_time seconds"

    echo "Scan completed. Results saved in $OUTPUT_FILE."
}

trap cleanup SIGINT SIGTERM

# Ensure ZMap is installed
if ! command -v zmap &> /dev/null; then
    echo "ZMap not found. Please install it. You can install it with: apt install zmap"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Start ICMP scan and save only responding IPs
echo "Scanning..."
zmap -M icmp_echoscan -o "$OUTPUT_FILE" -B "$BANDWIDTH" -f "saddr" -N "$MAX_IPS"

if [ $? -ne 0 ]; then
    echo "ZMap scan failed."
    exit 1
fi

cleanup

exit 0
