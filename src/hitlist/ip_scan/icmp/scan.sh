#!/bin/bash

OUTPUT_DIR="$1"
MAX_IPS="$2"

source src/hitlist/ip_scan/setup.sh "$OUTPUT_DIR"

zmap -o "$OUTPUT_FILE" -N "$MAX_IPS" -B "$BANDWIDTH" -M icmp_echoscan --output-fields=saddr --output-filter='classification=echoreply && repeat=0' --no-header-row

source src/hitlist/ip_scan/cleanup.sh "$OUTPUT_FILE"
