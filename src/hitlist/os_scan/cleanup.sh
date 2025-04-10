#!/bin/bash

OUTPUT_FILE="$1"
TEMP_FILE="$2"

# Move the temporary file to the input file
mv "$TEMP_FILE" "$OUTPUT_FILE" || { echo "Failed to move temp file"; exit 1; }

# Calculate end time and runtime
END_TIME=$(date +%s)
RUNTIME=$((END_TIME - START_TIME))

# Get the final line count and calculate the difference
FINAL_COUNT=$(wc -l < "$OUTPUT_FILE")
DIFF_COUNT=$((INITIAL_COUNT - FINAL_COUNT))

# Output the results
echo "OS scan finished successfully: hits=$FINAL_COUNT misses=$DIFF_COUNT runtime=$RUNTIME seconds"

# Add header row to the file
sed -i '1i IP,OS' "$OUTPUT_FILE" || { echo "Failed to add header"; exit 1; }

# Compress the file
OUTPUT_COMPRESSED_FILE="${OUTPUT_FILE}.zst"
zstd -f "$OUTPUT_FILE" -o "$OUTPUT_COMPRESSED_FILE" || { echo "Failed to compress file"; exit 1; }

if [ $? -eq 0 ]; then
  rm "$OUTPUT_FILE"
fi

echo "Results saved in $OUTPUT_COMPRESSED_FILE"
