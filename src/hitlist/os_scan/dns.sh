#!/bin/bash

INPUT_FILE="$1"

source src/hitlist/os_scan/setup.sh "$INPUT_FILE"
trap 'source src/hitlist/os_scan/cleanup.sh "$INPUT_FILE" "$TEMP_FILE"' EXIT

process_ip_addr() {
    ip="$1"
    os_name=$(dig @"$ip" version.bind CH TXT +short +retry=0 +time=1 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '"')

    # Ensure dig command ran successfully and os_name is non-empty
    if [[ $? -eq 0 && -n "$os_name" && "$os_name" != *"error"* && "$os_name" =~ $OS_REGEX ]]; then
        echo "IP: $ip - OS: $os_name"
        echo "$ip,$os_name" >> "$TEMP_FILE"
    else
        echo "Error: Unable to get OS for IP: $ip" >&2
    fi
}

# Use parallel to process IP addresses in parallel
parallel -a "$INPUT_FILE" -j 30 process_ip_addr

source src/hitlist/os_scan/cleanup.sh "$INPUT_FILE" "$TEMP_FILE"
