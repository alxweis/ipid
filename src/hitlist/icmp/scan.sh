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

# Include Cleanup functions
source src/hitlist/cleanup.sh

# Trap definition to call the cleanup function properly
trap cleanup SIGINT SIGTERM EXIT

# Ensure ZMap is installed
if ! command -v zmap &> /dev/null; then
    echo "ZMap not found. Please install it. You can install it with: apt install zmap"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Start scan and save only responding IPs
echo "Scanning..."
zmap -p "$PORT" -o "$OUTPUT_FILE" -N "$MAX_IPS" -B "$BANDWIDTH" -M icmp_echoscan --output-fields=saddr --output-filter='success=1 && repeat=0' --no-header-row

if [ $? -ne 0 ]; then
    echo "ZMap scan failed."
    exit 1
fi

echo "Scan completed successfully"
exit 0
