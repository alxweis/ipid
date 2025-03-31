#!/bin/bash

# Ensure OUTPUT_DIR is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <OUTPUT_DIR>"
    exit 1
fi

# Configuration
OUTPUT_DIR=$1
OUTPUT_FILE="${OUTPUT_DIR}/targets.csv"
BANDWIDTH=100M

cleanup() {
    sed -i '1s/^saddr/IP/' "$OUTPUT_FILE"
    awk '!seen[$0]++' "$OUTPUT_FILE" > temp && mv temp "$OUTPUT_FILE"
    echo "Scan completed. Results saved in $OUTPUT_FILE."
}

trap cleanup SIGINT SIGTERM

# Ensure ZMap is installed
if ! command -v zmap &> /dev/null
then
    echo "ZMap not found. Please install it with: apt install zmap"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Start ICMP scan and save only responding IPs
echo "Scanning..."
zmap -M icmp_echoscan -o "$OUTPUT_FILE" -B $BANDWIDTH -f "saddr"

if [ $? -ne 0 ]; then
    echo "Zmap scan failed."
    cleanup
    exit 1
fi

cleanup
