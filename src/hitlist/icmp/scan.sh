#!/bin/bash

# Ensure OUTPUT_DIR and MAX_IPS are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <OUTPUT_DIR> <MAX_IPS>"
    exit 1
fi

# Configuration
OUTPUT_DIR=$1
MAX_IPS=$2
OUTPUT_FILE="${OUTPUT_DIR}/targets.csv"
BANDWIDTH=100M

cleanup() {
    sed -i '1s/^saddr/IP/' "$OUTPUT_FILE"
  # TODO Unique Check
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
zmap -M icmp_echoscan -o "$OUTPUT_FILE" -B $BANDWIDTH -f "saddr" -N $MAX_IPS

if [ $? -ne 0 ]; then
    echo "ZMap scan failed."
    cleanup
    exit 1
fi

cleanup
