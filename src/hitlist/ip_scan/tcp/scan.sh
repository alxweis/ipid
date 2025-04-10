#!/bin/bash

OUTPUT_DIR="$1"
PORT="$2"
MAX_IPS="$3"
ENABLE_OS_SCAN="$4"

source src/hitlist/ip_scan/setup.sh "$OUTPUT_DIR"

zmap -p "$PORT" -o "$OUTPUT_FILE" -N "$MAX_IPS" -B "$BANDWIDTH" -M tcp_synscan --output-fields=saddr --output-filter='classification!=icmp && repeat=0' --no-header-row

source src/hitlist/ip_scan/cleanup.sh "$OUTPUT_FILE"

if [ "$ENABLE_OS_SCAN" == "True" ]; then
  echo "Executing: python3 0_hitlist.py os_scan $OUTPUT_FILE"
  python3 0_hitlist.py os_scan "$OUTPUT_FILE"
fi
