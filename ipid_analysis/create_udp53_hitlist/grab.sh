#!/bin/bash

INPUT="ips.txt"
OUTPUT="../../targets/ip_to_device_udp53.csv"

OS_REGEX="ubuntu|centos|debian|redhat|ret hat|rhel|fedora|gentoo|opensuse|euleros|zorin|linux|windows server|windows|freebsd|openbsd|netbsd|bsd|macos|darwin|solaris|fritz|rasp|openwrt|lede|dd-wrt|ddwrt|wrt|vyos|vyatta|pfsense|routeros|mikrotik|edgeos|airos|unifi|ubiquiti|junos|juniper|cisco ios|ios-xe|nx-os|ios|cisco|fortios|fortinet|forti|sonicos|sonicwall|sonic|arubaos|aruba|draytek|drayos|vigor|dray|zynos|zyxel|aix|hp-ux|hpux|z/os|zos|openvms|vms|vrp|busybox|vxworks|qnx|freertos|openembedded|yocto|utm|gaia|router"

echo "[*] Start digging and filtering results..."
echo "IP Address,Device Info" > "$OUTPUT"

process_ip() {
    ip=$1
    result=$(dig @"$ip" version.bind CH TXT +short +retry=0 +time=1 | tr '[:upper:]' '[:lower:]' | tr -d '"')

    if [[ $? -eq 0 && -n $result && $result != *"error"* && $result =~ $OS_REGEX ]]; then
        echo "[*] IP: $ip - Result: $result"
        echo "$ip,$result" >> "$OUTPUT"
    fi
}

export -f process_ip
export OUTPUT OS_REGEX

parallel -a "$INPUT" -j 30 process_ip

echo "[*] Results saved in $OUTPUT."
