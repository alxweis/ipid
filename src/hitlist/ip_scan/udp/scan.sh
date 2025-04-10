#!/bin/bash

PORT="$1"
OUTPUT_DIR="$2"
MAX_IPS="$3"
ENABLE_OS_SCAN="$4"

source src/hitlist/ip_scan/setup.sh "$OUTPUT_DIR"

declare -A SERVICE_MAP=(
    [53]="dns"
    [123]="ntp"
    [161]="snmp"
)
SERVICE="${SERVICE_MAP[$PORT]}"
SERVICE_BIN="src/hitlist/ip_scan/udp/${SERVICE}.bin"

zmap -p "$PORT" -o "$OUTPUT_FILE" -N "$MAX_IPS" -B "$BANDWIDTH" -M udp --probe-args="file:$SERVICE_BIN" --output-fields=saddr --output-filter='success=1 && repeat=0' --no-header-row

source src/hitlist/ip_scan/cleanup.sh "$OUTPUT_FILE"

if [ "$ENABLE_OS_SCAN" == "True" ]; then
  python3 0_hitlist.py os_scan "$OUTPUT_FILE"
fi
