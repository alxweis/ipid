#!/bin/bash

OUTPUT_FILE="$1"

count_lines() {
    wc -l < "$1"
}

INITIAL_COUNT=$(count_lines "$OUTPUT_FILE")

# Deduplicate
START_TIME_DEDUP=$(date +%s)

TEMP_FILE=$(mktemp "${OUTPUT_FILE}.dedup.XXXXXX" -p .)
LC_ALL=C sort -t',' -k1,1 -u -T . "$OUTPUT_FILE" > "$TEMP_FILE"
mv "$TEMP_FILE" "$OUTPUT_FILE"

END_TIME_DEDUP=$(date +%s)
RUNTIME_DEDUP=$((END_TIME_DEDUP - START_TIME_DEDUP))
UNIQUE_IPS=$(count_lines "$OUTPUT_FILE")
REMOVED_IPS=$((INITIAL_COUNT - UNIQUE_IPS))
echo "Deduplication finished successfully: removed_ips=$REMOVED_IPS runtime=$RUNTIME_DEDUP seconds"

# Shuffle
START_TIME_SHUFFLE=$(date +%s)

TEMP_FILE=$(mktemp "${OUTPUT_FILE}.shuffle.XXXXXX" -p .)
split -l 1000000 "$OUTPUT_FILE" parts_
for f in parts_*; do shuf "$f" > "$f.tmp" && mv "$f.tmp" "$f"; done
cat parts_* > "$TEMP_FILE"
rm parts_*
mv "$TEMP_FILE" "$OUTPUT_FILE"

END_TIME_SHUFFLE=$(date +%s)
RUNTIME_SHUFFLE=$((END_TIME_SHUFFLE - START_TIME_SHUFFLE))
echo "Shuffle finished successfully: runtime=$RUNTIME_SHUFFLE seconds"

final_count=$(count_lines "$OUTPUT_FILE")
echo "IP Scan finished successfully: final_count=$final_count"

# Add header
sed -i '1i IP,TS' "$OUTPUT_FILE" || { echo "Failed to add header"; exit 1; }

# Compress the file
OUTPUT_COMPRESSED_FILE="${OUTPUT_FILE}.zst"
zstd -f "$OUTPUT_FILE" -o "$OUTPUT_COMPRESSED_FILE" || { echo "Failed to compress file"; exit 1; }

if [ $? -eq 0 ]; then
  rm "$OUTPUT_FILE"
fi

OUTPUT_FILE=$OUTPUT_COMPRESSED_FILE
echo "Results saved in $OUTPUT_FILE"
