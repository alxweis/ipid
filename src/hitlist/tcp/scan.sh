#!/bin/bash

# Ensure PORT, OUTPUT_DIR and MAX_IPS are provided
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <port> <output_dir> <max_ips>"
    exit 1
fi

# Configuration
PORT="$1"
OUTPUT_DIR="$2"
MAX_IPS="$3"
OUTPUT_FILE="${OUTPUT_DIR}/targets.csv"
BANDWIDTH="100M"

# Include Cleanup functions
source src/hitlist/cleanup.sh

# Trap definition to call the cleanup function properly
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
zmap -M tcp_synscan -p "$PORT" -o "$OUTPUT_FILE" -B "$BANDWIDTH" -f "saddr" -N "$MAX_IPS" # TODO -b black_list

if [ $? -ne 0 ]; then
    echo "ZMap scan failed."
    exit 1
fi

cleanup

exit 0
