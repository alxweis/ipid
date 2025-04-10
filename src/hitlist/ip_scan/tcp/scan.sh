#!/bin/bash

PORT="$1"
OUTPUT_DIR="$2"
MAX_IPS="$3"
ENABLE_OS_SCAN="$4"

source src/hitlist/ip_scan/setup.sh "$OUTPUT_DIR"
trap 'source src/hitlist/ip_scan/cleanup.sh "$OUTPUT_FILE"' EXIT

zmap -p "$PORT" -o "$OUTPUT_FILE" -N "$MAX_IPS" -B "$BANDWIDTH" -M tcp_synscan --output-fields=saddr --output-filter='classification!=icmp && repeat=0' --no-header-row

source src/hitlist/ip_scan/cleanup.sh "$OUTPUT_FILE"
