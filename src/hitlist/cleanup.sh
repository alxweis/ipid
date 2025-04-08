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
    echo "Initial number of IP addresses: $initial_count"

    # Deduplicate
    start_dedup=$(date +%s)
    TEMP_FILE=$(mktemp "${OUTPUT_FILE}.dedup.XXXXXX" -p .)
    LC_ALL=C sort -u -T . "$OUTPUT_FILE" > "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    end_dedup=$(date +%s)
    dedup_time=$((end_dedup - start_dedup))
    deduped_count=$(count_lines "$OUTPUT_FILE")
    deduped_diff=$((initial_count - deduped_count))
    echo "Deduplication: removed_count=$deduped_diff runtime=$dedup_time seconds"

    # Shuffle
    start_shuffle=$(date +%s)
    TEMP_FILE=$(mktemp "${OUTPUT_FILE}.shuffle.XXXXXX" -p .)
    shuf "$OUTPUT_FILE" > "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    end_shuffle=$(date +%s)
    shuffle_time=$((end_shuffle - start_shuffle))
    echo "Shuffle: runtime=$shuffle_time seconds"

    # Add header
    sed -i '1i IP' "$OUTPUT_FILE"

    final_count=$(count_lines "$OUTPUT_FILE")
    echo "Final number of IP addresses: $final_count"
    echo "Results saved in $OUTPUT_FILE"
}
