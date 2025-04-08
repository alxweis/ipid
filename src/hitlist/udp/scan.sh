#!/bin/bash

# Ensure PORT, OUTPUT_DIR and MAX_IPS are provided
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
    echo "Usage: $0 <port> <output_dir> <max_ips>"
    exit 1
fi

# Configuration
PORT="$1"
SERVICE="$2"
OUTPUT_DIR="$3"
MAX_IPS="$4"
OUTPUT_FILE="${OUTPUT_DIR}/targets.csv"
BANDWIDTH="100M"

# Validate SERVICE argument
if [[ ! "$SERVICE" =~ ^(dns|ntp|snmp)$ ]]; then
    echo "Error: Invalid service. Allowed values are 'dns', 'ntp', or 'snmp'."
    exit 1
fi

# Ensure the corresponding .bin file exists
SERVICE_BIN="src/hitlist/udp/${SERVICE}.bin"
if [ ! -f "$SERVICE_BIN" ]; then
    echo "Error: The file '$SERVICE_BIN' does not exist. Please generate the payload first."
    exit 1
fi

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
zmap -p "$PORT" -o "$OUTPUT_FILE" -N "$MAX_IPS" -B "$BANDWIDTH" -M udp --probe-args="file:$SERVICE_BIN" --output-fields=saddr --output-filter='success=1 && repeat=0' --no-header-row

if [ $? -ne 0 ]; then
    echo "ZMap scan failed."
    exit 1
fi

echo "Scan completed successfully"
exit 0
