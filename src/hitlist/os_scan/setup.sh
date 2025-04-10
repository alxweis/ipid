#!/bin/bash

INPUT_FILE="$1"
OS_REGEX="ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos|openembedded|yocto|utm|gaia|router"
export OS_REGEX

# Decompress the file
zstd -f -d "$INPUT_FILE" || { echo "Failed to decompress file"; exit 1; }
INPUT_FILE="${INPUT_FILE%.zst}"
export INPUT_FILE

# Check if already scanned
HEADER=$(head -n 1 "$INPUT_FILE")
if [[ "$HEADER" == *"IP,OS"* ]]; then
  echo "OS already scanned. Recompressing file."
  zstd -f "$INPUT_FILE" -o "${INPUT_FILE}.zst"
  if [ $? -eq 0 ]; then
    rm "$INPUT_FILE"
  fi
  exit 0
fi

# Remove the header row
sed -i '1d' "$INPUT_FILE" || { echo "Failed to remove header"; exit 1; }

# Get initial line count and export
INITIAL_COUNT=$(wc -l < "$INPUT_FILE")
export INITIAL_COUNT

# Store start time and export
START_TIME=$(date +%s)
export START_TIME

# Create temporary file for the scan
TEMP_FILE=$(mktemp "${INPUT_FILE}.os_scan.XXXXXX" -p .)
export TEMP_FILE
