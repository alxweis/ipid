#!/bin/bash

INPUT="ips.txt"
OUTPUT="../../targets/ip_to_device_tcp80.csv"

OS_REGEX="ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos|openembedded|yocto|utm|gaia|router"

echo "[*] Start banner grabbing and filtering results..."
echo "IP Address,Device Info" > $OUTPUT

zgrab2 http --port 80 --input-file=$INPUT --timeout 5 | \
jq -r --arg regex "$OS_REGEX" '. |
  select(.data? != null) |
  select(.data.http? != null) |
  select(.data.http.result? != null) |
  select(.data.http.result.response? != null) |
  select(.data.http.result.response.headers? != null) |
  select(.data.http.result.response.headers.server? != null) |
  select(.data.http.result.response.headers.server | map(ascii_downcase) | join(",") | test($regex)) |
  "\(.ip),\(.data.http.result.response.headers.server)"' >> $OUTPUT

# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
    echo "[!] Banner grabbing or filtering failed."
    exit 1
fi

echo "[*] Results saved in $OUTPUT"