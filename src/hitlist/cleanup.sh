#!/bin/bash

# Check if the required environment variables are set
if [ -z "$OUTPUT_FILE" ]; then
    echo "Error: OUTPUT_FILE is not set."
    exit 1
fi

# Function to count lines efficiently
count_lines() {
    wc -l < "$1"
}

cleanup() {
    # Count initial IPs
    initial_count=$(count_lines "$OUTPUT_FILE")
    echo "Initial number of IPs: $initial_count"

    # Deduplicate
    start_dedup=$(date +%s)
    TEMP_FILE=$(mktemp "${OUTPUT_FILE}.dedup.XXXXXX" -p .)
    sort -u -T . "$OUTPUT_FILE" | LC_ALL=C > "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    end_dedup=$(date +%s)
    dedup_time=$((end_dedup - start_dedup))

    deduped_count=$(count_lines "$OUTPUT_FILE")
    deduped_diff=$((initial_count - deduped_count))
    echo "Number of IPs removed by deduplication: $deduped_diff"

    # Shuffle
    start_shuffle=$(date +%s)
    TEMP_FILE=$(mktemp "${OUTPUT_FILE}.shuffle.XXXXXX" -p .)
    shuf "$OUTPUT_FILE" > "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    end_shuffle=$(date +%s)
    shuffle_time=$((end_shuffle - start_shuffle))

    final_count=$(count_lines "$OUTPUT_FILE")
    echo "Final number of IPs: $final_count"

    # Add header
    sed -i '1i IP' "$OUTPUT_FILE"

    echo "Deduplication took: $dedup_time seconds"
    echo "Shuffling took: $shuffle_time seconds"

    echo "Results saved in $OUTPUT_FILE"
}
